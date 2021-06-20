#include <amount.h>
#include <array>
#include <coins.h>
#include <hash.h>
#include <index/blockproofindex.h>
#include <node/blockstorage.h>
#include <script/script.h>
#include <uint256.h>
#include <undo.h>
#include <util/system.h>
#include <utility>
#include <utreexoutils.h>
#include <validation.h>
#include <vector>

// Build time verification options. These make the index slow and
// are meant for debugging/testing.
//
// Verify each forest modification with the equivalent modification and
// verification on a pollard.
#define VERIFY_POLLARD 0
// Verify each forest modification by undoing it and re-modifying.
#define VERIFY_UNDO 0

std::unique_ptr<BlockProofIndex> g_blockproofindex;

constexpr uint8_t DB_BLOCK_HASH{'s'};
constexpr uint8_t DB_BLOCK_HEIGHT{'t'};
constexpr uint8_t DB_BLOCKPROOF_POS{'P'};
constexpr uint8_t DB_UNDOBATCH_POS{'U'};

constexpr unsigned int MAX_PROOF_FILE_SIZE = 0x8000000; // 128 MiB
/** The pre-allocation chunk size for proof?????.dat files */
constexpr unsigned int PROOF_FILE_CHUNK_SIZE = 0x1000000; // 16 MiB

struct DBVal {
    FlatFilePos m_proof_pos;
    FlatFilePos m_undo_pos;
    int m_proof_size;
    int m_undo_size;

    SERIALIZE_METHODS(DBVal, obj) { READWRITE(obj.m_proof_pos,
                                              obj.m_undo_pos,
                                              obj.m_proof_size,
                                              obj.m_undo_size); }
};

struct DBHeightKey {
    int height;

    explicit DBHeightKey(int height_in) : height(height_in) {}

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ser_writedata8(s, DB_BLOCK_HEIGHT);
        ser_writedata32be(s, height);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        const uint8_t prefix{ser_readdata8(s)};
        if (prefix != DB_BLOCK_HEIGHT) {
            throw std::ios_base::failure("Invalid format for block proof index DB height key");
        }
        height = ser_readdata32be(s);
    }
};

struct DBHashKey {
    uint256 hash;

    explicit DBHashKey(const uint256& hash_in) : hash(hash_in) {}

    SERIALIZE_METHODS(DBHashKey, obj)
    {
        uint8_t prefix{DB_BLOCK_HASH};
        READWRITE(prefix);
        if (prefix != DB_BLOCK_HASH) {
            throw std::ios_base::failure("Invalid format for block proof index DB hash key");
        }

        READWRITE(obj.hash);
    }
};

BlockProofIndex::BlockProofIndex(size_t n_cache_size, bool f_memory, bool f_wipe)
{
    fs::path path = gArgs.GetDataDirNet() / "indexes" / GetName();
    fs::create_directories(path);

    m_db = std::make_unique<BaseIndex::DB>(path / "db", n_cache_size, f_memory, f_wipe);
    m_proof_fileseq = std::make_unique<FlatFileSeq>(path, "proof", PROOF_FILE_CHUNK_SIZE);
    m_undo_fileseq = std::make_unique<FlatFileSeq>(path, "undo", PROOF_FILE_CHUNK_SIZE);
    fs::path forest_path = gArgs.GetDataDirNet() / "indexes" / GetName() / "forest.dat";
    m_forest = std::make_unique<utreexo::RamForest>(forest_path.c_str());

#if VERIFY_POLLARD
    // Create the pollard from the forest.
    std::vector<utreexo::Hash> roots;
    m_forest->Roots(roots);
    m_pollard = std::make_unique<utreexo::Pollard>(roots, m_forest->NumLeaves());
#endif
}

bool BlockProofIndex::LookupRawBlockProof(const CBlockIndex* index, std::vector<uint8_t>& proof_bytes) const
{
    std::pair<uint256, DBVal> value;
    // Try reading by height.
    if (!m_db->Read(DBHeightKey{index->nHeight}, value)) {
        // Read by hash if proof is not found by height.
        if (!m_db->Read(DBHashKey{index->GetBlockHash()}, value)) {
            return false;
        }
    }

    CAutoFile file(m_proof_fileseq->Open(value.second.m_proof_pos), SER_DISK, CLIENT_VERSION);
    if (file.IsNull()) {
        return error("%s: Failed to open proof file %d", __func__, value.second.m_proof_pos.nFile);
    }

    proof_bytes.resize(value.second.m_proof_size);
    file.read(reinterpret_cast<char*>(proof_bytes.data()), proof_bytes.size());

    return true;
}

bool BlockProofIndex::LookupBlockProof(int height, UtxoSetInclusionProof& proof) const
{
    std::pair<uint256, DBVal> value;
    if (!m_db->Read(DBHeightKey{height}, value)) {
        return false;
    }

    CAutoFile file(m_proof_fileseq->Open(value.second.m_proof_pos), SER_DISK, CLIENT_VERSION);
    if (file.IsNull()) {
        return error("%s: Failed to open proof file %d", __func__, value.second.m_proof_pos.nFile);
    }

    file >> proof;
    return true;
}

bool BlockProofIndex::LookupUndoBatch(int height, utreexo::UndoBatch& undo) const
{
    std::pair<uint256, DBVal> value;
    if (!m_db->Read(DBHeightKey{height}, value)) {
        return false;
    }

    CAutoFile file(m_undo_fileseq->Open(value.second.m_undo_pos), SER_DISK, CLIENT_VERSION);
    if (file.IsNull()) {
        return error("%s: Failed to open undo file %d", __func__, value.second.m_undo_pos.nFile);
    }

    std::vector<uint8_t> bytes;
    bytes.resize(value.second.m_undo_size);
    file.read((char*)bytes.data(), bytes.size());

    return undo.Unserialize(bytes);
}

bool BlockProofIndex::Init()
{
    if (!m_db->Read(DB_BLOCKPROOF_POS, m_next_proof_pos)) {
        // Check that the cause of the read failure is that the key does not exist. Any other errors
        // indicate database corruption or a disk failure, and starting the index would cause
        // further corruption.
        if (m_db->Exists(DB_BLOCKPROOF_POS)) {
            return error("%s: Cannot read current %s state; index may be corrupted",
                         __func__, GetName());
        }

        // If the DB_TTLBLOCK_POS is not set, then initialize to the first location.
        m_next_proof_pos.nFile = 0;
        m_next_proof_pos.nPos = 0;
    }

    if (!m_db->Read(DB_UNDOBATCH_POS, m_next_undo_pos)) {
        // Check that the cause of the read failure is that the key does not exist. Any other errors
        // indicate database corruption or a disk failure, and starting the index would cause
        // further corruption.
        if (m_db->Exists(DB_UNDOBATCH_POS)) {
            return error("%s: Cannot read current %s state; index may be corrupted",
                         __func__, GetName());
        }

        // If the DB_TTLBLOCK_POS is not set, then initialize to the first location.
        m_next_undo_pos.nFile = 0;
        m_next_undo_pos.nPos = 0;
    }

    return BaseIndex::Init();
}

bool BlockProofIndex::CommitInternal(CDBBatch& batch)
{
    // Flush current proof file to disk.
    CAutoFile proof_file(m_proof_fileseq->Open(m_next_proof_pos), SER_DISK, CLIENT_VERSION);
    if (proof_file.IsNull()) {
        return error("%s: Failed to open proof file %d", __func__, m_next_proof_pos.nFile);
    }
    if (!FileCommit(proof_file.Get())) {
        return error("%s: Failed to commit proof file %d", __func__, m_next_proof_pos.nFile);
    }

    // Flush current undo file to disk.
    CAutoFile undo_file(m_undo_fileseq->Open(m_next_undo_pos), SER_DISK, CLIENT_VERSION);
    if (undo_file.IsNull()) {
        return error("%s: Failed to open undo file %d", __func__, m_next_undo_pos.nFile);
    }
    if (!FileCommit(undo_file.Get())) {
        return error("%s: Failed to commit undo file %d", __func__, m_next_undo_pos.nFile);
    }

    batch.Write(DB_BLOCKPROOF_POS, m_next_proof_pos);
    batch.Write(DB_UNDOBATCH_POS, m_next_undo_pos);
    m_forest->Commit();

    return BaseIndex::CommitInternal(batch);
}

size_t BlockProofIndex::WriteProofToDisk(FlatFilePos& pos, const UtxoSetInclusionProof& proof)
{
    size_t bytes_to_write = GetSerializeSize(proof, SER_DISK);

    // If writing the proof would overflow the file, flush and move to the next one.
    if (pos.nPos + bytes_to_write > MAX_PROOF_FILE_SIZE) {
        CAutoFile last_file(m_proof_fileseq->Open(pos), SER_DISK, CLIENT_VERSION);
        if (last_file.IsNull()) {
            LogPrintf("%s: Failed to open filter file %d\n", __func__, pos.nFile);
            return 0;
        }
        if (!TruncateFile(last_file.Get(), pos.nPos)) {
            LogPrintf("%s: Failed to truncate filter file %d\n", __func__, pos.nFile);
            return 0;
        }
        if (!FileCommit(last_file.Get())) {
            LogPrintf("%s: Failed to commit filter file %d\n", __func__, pos.nFile);
            return 0;
        }

        pos.nFile++;
        pos.nPos = 0;
    }

    // Pre-allocate sufficient space for filter data.
    bool out_of_space;
    m_proof_fileseq->Allocate(pos, bytes_to_write, out_of_space);
    if (out_of_space) {
        LogPrintf("%s: out of disk space\n", __func__);
        return 0;
    }

    CAutoFile fileout(m_proof_fileseq->Open(pos), SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull()) {
        LogPrintf("%s: Failed to open filter file %d\n", __func__, pos.nFile);
        return 0;
    }
    fileout << proof;

    return bytes_to_write;
}

size_t BlockProofIndex::WriteUndoBatchToDisk(FlatFilePos& pos, const utreexo::UndoBatch& undo)
{
    std::vector<uint8_t> undo_bytes;
    undo.Serialize(undo_bytes);

    // If writing the filter would overflow the file, flush and move to the next one.
    if (pos.nPos + undo_bytes.size() > MAX_PROOF_FILE_SIZE) {
        CAutoFile last_file(m_undo_fileseq->Open(pos), SER_DISK, CLIENT_VERSION);
        if (last_file.IsNull()) {
            LogPrintf("%s: Failed to open filter file %d\n", __func__, pos.nFile);
            return 0;
        }
        if (!TruncateFile(last_file.Get(), pos.nPos)) {
            LogPrintf("%s: Failed to truncate filter file %d\n", __func__, pos.nFile);
            return 0;
        }
        if (!FileCommit(last_file.Get())) {
            LogPrintf("%s: Failed to commit filter file %d\n", __func__, pos.nFile);
            return 0;
        }

        pos.nFile++;
        pos.nPos = 0;
    }

    // Pre-allocate sufficient space for filter data.
    bool out_of_space;
    m_undo_fileseq->Allocate(pos, undo_bytes.size(), out_of_space);
    if (out_of_space) {
        LogPrintf("%s: out of disk space\n", __func__);
        return 0;
    }

    CAutoFile fileout(m_undo_fileseq->Open(pos), SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull()) {
        LogPrintf("%s: Failed to open filter file %d\n", __func__, pos.nFile);
        return 0;
    }

    fileout.write(reinterpret_cast<const char*>(undo_bytes.data()), undo_bytes.size());
    return undo_bytes.size();
}

bool BlockProofIndex::WriteBlock(const CBlock& block, const CBlockIndex* pindex)
{
    // We need the active chain to lookup the block hashes in which coins were
    // created.
    assert(m_chainstate);
    CChain& active_chain = m_chainstate->m_chain;

    if (pindex->nHeight == 0) return true;

    // Read the undo data from disk.
    // The undo data holds the coins that are being spend by this block.
    CBlockUndo block_undo;
    if (pindex->nHeight > 0 && !UndoReadFromDisk(block_undo, pindex)) {
        return error("%s could not read undo block", __func__);
    }

    std::vector<int> in_skip, out_skip;
    ComputeBlockSkipLists(block, in_skip, out_skip);

    std::vector<UtreexoLeafData> target_leaves;
    std::vector<ReconstructableCoin> coins;
    for (const CTxUndo& tx_undo : block_undo.vtxundo) {
        for (const Coin& coin : tx_undo.vprevout) {
            coins.push_back(ReconstructableCoin(coin));
        }
    }
    if (!ReconstructLeavesFromTransactions(active_chain, block.vtx, coins, in_skip, true, target_leaves)) {
        return error("%s could not create targets from transactions", __func__);
    }

    std::vector<utreexo::Hash> target_hashes;
    for (const UtreexoLeafData& leaf_data : target_leaves) {
        CHashWriter writer(SER_GETHASH, PROTOCOL_VERSION);
        writer << leaf_data;
        target_hashes.push_back(writer.GetHash256());
    }

    utreexo::BatchProof block_proof;
    if (!m_forest->Prove(block_proof, target_hashes)) {
        return error("%s failed to create proof for block %d", __func__, pindex->nHeight);
    }

    UtxoSetInclusionProof proof(std::move(target_leaves), std::move(block_proof));
    size_t bytes_written = WriteProofToDisk(m_next_proof_pos, proof);
    if (bytes_written == 0) return error("%s failed to write proof to disk for block %d", __func__, pindex->nHeight);

#if VERIFY_POLLARD
    // Sort target hashes.
    std::vector<std::array<uint8_t, 32>> sorted_target_hashes;
    sorted_target_hashes.reserve(target_hashes.size());
    SortTargetHashes(proof.GetProof(), target_hashes, sorted_target_hashes);

    // Check if a pollard could verify this proof.
    if (!m_pollard->Verify(block_proof, sorted_target_hashes)) {
        return error("%s failed to verify proof for block %d", __func__, pindex->nHeight);
    }
#endif

    std::vector<UtreexoLeafData> new_leaves;
    GetNewLeavesFromBlock(block, pindex->nHeight, out_skip, new_leaves);

    std::vector<std::pair<std::array<uint8_t, 32>, bool>> leaves;
    for (const UtreexoLeafData& leaf_data : new_leaves) {
        CHashWriter writer(SER_GETHASH, PROTOCOL_VERSION);
        writer << leaf_data;
        leaves.emplace_back(writer.GetHash256(), false);
    }

    utreexo::UndoBatch undo;
    if (!m_forest->Modify(undo, leaves, proof.GetProof().GetSortedTargets())) {
        return error("%s failed to modify the accumulator for block %d", __func__, pindex->nHeight);
    }

    size_t undo_bytes_written = WriteUndoBatchToDisk(m_next_undo_pos, undo);
    if (undo_bytes_written == 0) return error("%s failed to write undo to disk for block %d", __func__, pindex->nHeight);

#if VERIFY_UNDO
    if (!m_forest->Undo(undo)) {
        return error("%s failed to undo the accumulator for block %d", __func__, pindex->nHeight);
    }

    utreexo::UndoBatch unused_undo;
    if (!m_forest->Modify(unused_undo, leaves, proof.GetProof().GetSortedTargets())) {
        return error("%s failed to modify the accumulator for block %d", __func__, pindex->nHeight);
    }
#endif

#if VERIFY_POLLARD
    if (!m_pollard->Modify(leaves, block_proof.GetSortedTargets())) {
        return error("%s failed to modify the accumulator for block %d", __func__, pindex->nHeight);
    }
#endif


    DBVal value{m_next_proof_pos,
                m_next_undo_pos,
                static_cast<int>(bytes_written),
                static_cast<int>(undo_bytes_written)};
    std::pair<uint256, DBVal> val;
    val.first = pindex->GetBlockHash();
    val.second = value;
    if (!m_db->Write(DBHeightKey{pindex->nHeight}, val)) {
        return error("%s failed to write to the proof position to the db at height %d", __func__, pindex->nHeight);
    }

    m_next_proof_pos.nPos += bytes_written;
    m_next_undo_pos.nPos += undo_bytes_written;

    return true;
}

bool BlockProofIndex::Rewind(const CBlockIndex* current_tip, const CBlockIndex* new_tip)
{
    assert(current_tip->GetAncestor(new_tip->nHeight) == new_tip);

    CDBBatch batch(*m_db);
    std::unique_ptr<CDBIterator> db_it(m_db->NewIterator());

    DBHeightKey key(new_tip->nHeight);
    db_it->Seek(key);

    std::vector<utreexo::UndoBatch> undos;
    for (int height = new_tip->nHeight; height <= current_tip->nHeight; ++height) {
        if (!db_it->GetKey(key) || key.height != height) {
            return error("%s: unexpected key in %s: expected (%c, %d)",
                         __func__, GetName(), DB_BLOCK_HEIGHT, height);
        }

        std::pair<uint256, DBVal> value;
        if (!db_it->GetValue(value)) {
            return error("%s: unable to read value in %s at key (%c, %d)",
                         __func__, GetName(), DB_BLOCK_HEIGHT, height);
        }

        utreexo::UndoBatch undo;
        if (!LookupUndoBatch(height, undo)) {
            return error("%s: unable to read undo in %s at key (%c, %d)",
                         __func__, GetName(), DB_BLOCK_HEIGHT, height);
        }
        undos.emplace_back(std::move(undo));

        batch.Write(DBHashKey(value.first), std::move(value));

        db_it->Next();
    }

    // Go in reverse and undo each block in the forest.
    for (auto it = undos.crbegin(); it != undos.crend(); ++it) {
        const utreexo::UndoBatch& undo = *it;
        if (!m_forest->Undo(undo)) {
            return error("could not undo forest");
        }
    }

#if VERIFY_POLLARD
    // Reset pollard
    m_pollard.reset();
    std::vector<utreexo::Hash> roots;
    m_forest->Roots(roots);
    m_pollard = std::make_unique<utreexo::Pollard>(roots, m_forest->NumLeaves());
#endif

    batch.Write(DB_BLOCKPROOF_POS, m_next_proof_pos);
    batch.Write(DB_UNDOBATCH_POS, m_next_proof_pos);
    if (!m_db->WriteBatch(batch)) return false;

    return BaseIndex::Rewind(current_tip, new_tip);
}

BaseIndex::DB& BlockProofIndex::GetDB() const { return *m_db; }

