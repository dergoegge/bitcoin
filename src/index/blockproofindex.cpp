#include <array>
#include <coins.h>
#include <hash.h>
#include <index/blockproofindex.h>
#include <node/blockstorage.h>
#include <script/script.h>
#include <span.h>
#include <uint256.h>
#include <undo.h>
#include <util/system.h>
#include <utility>
#include <utreexoutils.h>
#include <validation.h>
#include <vector>

std::unique_ptr<BlockProofIndex> g_blockproofindex;

const char* BLOCK_PROOF_INDEX_NAME = "blockproofindex";

static constexpr uint8_t DB_BLOCK_HASH{'s'};
static constexpr uint8_t DB_BLOCK_HEIGHT{'t'};
static constexpr uint8_t DB_BLOCKPROOF_POS{'P'};

static constexpr unsigned int MAX_PROOF_FILE_SIZE{0x8000000}; // 128 MiB
/** The pre-allocation chunk size for proof?????.dat files */
static constexpr unsigned int PROOF_FILE_CHUNK_SIZE{0x1000000};      // 16 MiB
static constexpr unsigned int MAX_FOREST_CHUNK_FILE_SIZE{0x2000000}; // 32MiB

static constexpr uint64_t FOREST_ON_DISK_CHUNK_SIZE{100000};

struct DBVal {
    FlatFilePos m_proof_pos;
    int m_proof_size;

    uint64_t m_num_leaves;
    std::vector<utreexo::Hash> m_root_hashes;

    SERIALIZE_METHODS(DBVal, obj)
    {
        READWRITE(obj.m_proof_pos, obj.m_proof_size,
                  obj.m_root_hashes, obj.m_num_leaves);
    }
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
            throw std::ios_base::failure(
                "Invalid format for block proof index DB height key");
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
            throw std::ios_base::failure(
                "Invalid format for block proof index DB hash key");
        }

        READWRITE(obj.hash);
    }
};

bool ReadForestFromDisk(utreexo::Accumulator& forest);

BlockProofIndex::BlockProofIndex(size_t n_cache_size, bool f_memory, bool f_wipe)
{
    fs::path path = gArgs.GetDataDirNet() / "indexes" / GetName();
    fs::create_directories(path);

    m_db = std::make_unique<BaseIndex::DB>(path / "db", n_cache_size, f_memory, f_wipe);
    m_proof_fileseq = std::make_unique<FlatFileSeq>(path, "proof", PROOF_FILE_CHUNK_SIZE);
}


bool BlockProofIndex::LookupRawBlockProof(
    const CBlockIndex* index, std::vector<uint8_t>& proof_bytes) const
{
    std::pair<uint256, DBVal> value;
    // Try reading by height.
    if (!m_db->Read(DBHeightKey{index->nHeight}, value)) {
        // Read by hash if proof is not found by height.
        if (!m_db->Read(DBHashKey{index->GetBlockHash()}, value)) {
            return false;
        }
    }

    CAutoFile file(m_proof_fileseq->Open(value.second.m_proof_pos), SER_DISK,
                   CLIENT_VERSION);
    if (file.IsNull()) {
        return error("%s: Failed to open proof file %d", __func__,
                     value.second.m_proof_pos.nFile);
    }

    proof_bytes.resize(value.second.m_proof_size);
    file.read(AsWritableBytes(Span{proof_bytes}));

    return true;
}

bool BlockProofIndex::LookupBlockProof(int height,
                                       UtxoSetInclusionProof& proof) const
{
    std::pair<uint256, DBVal> value;
    if (!m_db->Read(DBHeightKey{height}, value)) {
        return false;
    }

    CAutoFile file(m_proof_fileseq->Open(value.second.m_proof_pos), SER_DISK,
                   CLIENT_VERSION);
    if (file.IsNull()) {
        return error("%s: Failed to open proof file %d", __func__,
                     value.second.m_proof_pos.nFile);
    }

    file >> proof;
    return true;
}

bool BlockProofIndex::ComputeProofForLeaves(
    const CBlockIndex* expected_tip,
    const std::vector<UtreexoLeaf>&& leaves, UtxoSetInclusionProof& proof)
{
    LOCK(m_forest_mutex);

    if (expected_tip != CurrentIndex()) return false;

    std::vector<utreexo::Hash> target_hashes;
    for (const UtreexoLeaf& leaf_data : leaves) {
        CHashWriter writer(SER_GETHASH, PROTOCOL_VERSION);
        writer << leaf_data;
        target_hashes.push_back(writer.GetHash256());
    }

    utreexo::BatchProof<utreexo::Hash> batch_proof;
    if (!m_forest->Prove(batch_proof, target_hashes)) return false;

    proof = UtxoSetInclusionProof(std::move(leaves), std::move(batch_proof));
    return true;
}

bool BlockProofIndex::Init()
{
    if (!BaseIndex::Init()) {
        return false;
    }

    if (!m_db->Read(DB_BLOCKPROOF_POS, m_next_proof_pos)) {
        // Check that the cause of the read failure is that the key does not
        // exist. Any other errors indicate database corruption or a disk
        // failure, and starting the index would cause further corruption.
        if (m_db->Exists(DB_BLOCKPROOF_POS)) {
            return error(
                "%s: Cannot read current %s state; index may be corrupted",
                __func__, GetName());
        }

        // If the DB_TTLBLOCK_POS is not set, then initialize to the first
        // location.
        m_next_proof_pos.nFile = 0;
        m_next_proof_pos.nPos = 0;
    }

    std::vector<utreexo::Hash> roots;
    uint64_t num_leaves{0};
    const CBlockIndex* best_block{CurrentIndex()};
    if (best_block) {
        std::pair<uint256, DBVal> value;
        if (!m_db->Read(DBHeightKey{best_block->nHeight}, value)) {
            return false;
        }

        num_leaves = value.second.m_num_leaves;
        roots = value.second.m_root_hashes;
    }

    LOCK(m_forest_mutex);
    m_forest = utreexo::Make(num_leaves, roots);
    if (!ReadForestFromDisk(*m_forest)) {
        return false;
    }

    return true;
}

size_t WriteForestChunkToDisk(FlatFileSeq& seq, FlatFilePos& pos,
                              const std::vector<utreexo::Hash>& chunk_hashes,
                              const utreexo::BatchProof<utreexo::Hash>& chunk_proof)
{
    size_t bytes_to_write = GetSerializeSize(chunk_hashes, SER_DISK);
    bytes_to_write += GetSerializeSize(chunk_proof.GetTargets(), SER_DISK);
    bytes_to_write += GetSerializeSize(chunk_proof.GetHashes(), SER_DISK);

    // If writing the proof would overflow the file, flush and move to the next
    // one.
    if (pos.nPos + bytes_to_write > MAX_FOREST_CHUNK_FILE_SIZE) {
        CAutoFile last_file(seq.Open(pos), SER_DISK, CLIENT_VERSION);
        if (last_file.IsNull()) {
            LogPrintf("%s: Failed to open filter file %d\n", __func__, pos.nFile);
            return 0;
        }
        if (!TruncateFile(last_file.Get(), pos.nPos)) {
            LogPrintf("%s: Failed to truncate forest file %d\n", __func__, pos.nFile);
            return 0;
        }
        if (!FileCommit(last_file.Get())) {
            LogPrintf("%s: Failed to commit forest file %d\n", __func__, pos.nFile);
            return 0;
        }

        pos.nFile++;
        pos.nPos = 0;
    }

    // Pre-allocate sufficient space for filter data.
    bool out_of_space;
    seq.Allocate(pos, bytes_to_write, out_of_space);
    if (out_of_space) {
        LogPrintf("%s: out of disk space\n", __func__);
        return 0;
    }

    CAutoFile forest_file(seq.Open(pos), SER_DISK, CLIENT_VERSION);
    if (forest_file.IsNull()) {
        LogPrintf("%s: Failed to open forest file %d\n", __func__, pos.nFile);
        return 0;
    }

    forest_file << chunk_hashes;
    forest_file << chunk_proof.GetTargets();
    forest_file << chunk_proof.GetHashes();

    return bytes_to_write;
}

/**
 * Commit the forest to disk in the form of a flat file series `forest_*.dat`.
 * The forest is stored in the form of multiple proofs for chunks of leaves
 * (FOREST_ON_DISK_CHUNK_SIZE).
 *
 * TODO: This is kinda slow, make it faster.
 */
bool WriteForestToDisk(const utreexo::Accumulator& forest)
{
    FlatFileSeq forest_file_seq{gArgs.GetDataDirNet() / "indexes" / BLOCK_PROOF_INDEX_NAME, "forest", PROOF_FILE_CHUNK_SIZE};
    FlatFilePos pos{0, 0};

    std::vector<utreexo::Hash> cached_leaves{forest.GetCachedLeaves()};
    auto chunk_begin = cached_leaves.begin();

    while (chunk_begin != cached_leaves.end()) {
        auto chunk_end{std::next(chunk_begin, std::min((uint64_t)std::distance(chunk_begin, cached_leaves.end()), FOREST_ON_DISK_CHUNK_SIZE))};

        std::vector<utreexo::Hash> chunk_hashes{chunk_begin, chunk_end};
        utreexo::BatchProof<utreexo::Hash> proof;
        if (!forest.Prove(proof, chunk_hashes)) {
            return false;
        }

        pos.nPos += WriteForestChunkToDisk(forest_file_seq, pos, chunk_hashes, proof);
        std::advance(chunk_begin, chunk_hashes.size());
    }

    return true;
}

bool ReadForestFromDisk(utreexo::Accumulator& forest)
{
    FlatFileSeq forest_file_seq{gArgs.GetDataDirNet() / "indexes" / BLOCK_PROOF_INDEX_NAME, "forest", PROOF_FILE_CHUNK_SIZE};
    FlatFilePos pos{0, 0};

    while (true) {
        FILE* file{forest_file_seq.Open(pos, /*read_only=*/true)};
        CBufferedFile forest_file{file, 1024 * 1024, 0, SER_DISK, CLIENT_VERSION};
        if (!file) {
            // The end of the flat file series has been reached.
            break;
        }
        std::vector<utreexo::Hash> chunk_hashes;
        forest_file >> chunk_hashes;
        std::vector<uint64_t> targets;
        forest_file >> targets;
        std::vector<utreexo::Hash> proof_hashes;
        forest_file >> proof_hashes;
		LogPrintf("%d, %d, %d\n", chunk_hashes.size(), targets.size(), proof_hashes.size());
        assert(chunk_hashes.size() > 0);
        assert(chunk_hashes.size() <= FOREST_ON_DISK_CHUNK_SIZE);

        size_t bytes_read = GetSerializeSize(chunk_hashes, SER_DISK);
        bytes_read += GetSerializeSize(targets, SER_DISK);
        bytes_read += GetSerializeSize(proof_hashes, SER_DISK);

        utreexo::BatchProof<utreexo::Hash> proof{targets, proof_hashes};
        if (!forest.Verify(proof, chunk_hashes)) {
            LogPrintf("%s: Failed to verify forest chunk %d\n", __func__, pos.nFile);
            return false;
        }

        LogPrintf("Read forest chunk file:%d,pos:%d\n", pos.nFile, pos.nPos);
        pos.nPos += bytes_read;

        if (chunk_hashes.size() < FOREST_ON_DISK_CHUNK_SIZE) {
            break;
        }

        if (forest_file.eof()) {
            pos = FlatFilePos{pos.nFile + 1, 0};
        }
    }

    return true;
}

bool BlockProofIndex::CommitInternal(CDBBatch& batch)
{
    // Flush current proof file to disk.
    CAutoFile proof_file(m_proof_fileseq->Open(m_next_proof_pos), SER_DISK,
                         CLIENT_VERSION);
    if (proof_file.IsNull()) {
        return error("%s: Failed to open proof file %d", __func__,
                     m_next_proof_pos.nFile);
    }
    if (!FileCommit(proof_file.Get())) {
        return error("%s: Failed to commit proof file %d", __func__,
                     m_next_proof_pos.nFile);
    }

    batch.Write(DB_BLOCKPROOF_POS, m_next_proof_pos);

    {
        LOCK(m_forest_mutex);
        if (!WriteForestToDisk(*Assume(m_forest))) {
            return error("%s: Failed to commit forest to disk\n", __func__);
        }
    }

    return BaseIndex::CommitInternal(batch);
}

size_t BlockProofIndex::WriteProofToDisk(FlatFilePos& pos,
                                         const UtxoSetInclusionProof& proof)
{
    size_t bytes_to_write = GetSerializeSize(proof, SER_DISK);

    // If writing the proof would overflow the file, flush and move to the next
    // one.
    if (pos.nPos + bytes_to_write > MAX_PROOF_FILE_SIZE) {
        CAutoFile last_file(m_proof_fileseq->Open(pos), SER_DISK,
                            CLIENT_VERSION);
        if (last_file.IsNull()) {
            LogPrintf("%s: Failed to open filter file %d\n", __func__,
                      pos.nFile);
            return 0;
        }
        if (!TruncateFile(last_file.Get(), pos.nPos)) {
            LogPrintf("%s: Failed to truncate filter file %d\n", __func__,
                      pos.nFile);
            return 0;
        }
        if (!FileCommit(last_file.Get())) {
            LogPrintf("%s: Failed to commit filter file %d\n", __func__,
                      pos.nFile);
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
    if (pindex->nHeight > 0 && !node::UndoReadFromDisk(block_undo, pindex)) {
        return error("%s could not read undo block", __func__);
    }

    // Create lists of input/output indexes that are spend in the same block.
    std::vector<int> in_skip, out_skip;
    ComputeBlockSkipLists(block, in_skip, out_skip);

    std::vector<Coin> coins;
    for (const CTxUndo& tx_undo : block_undo.vtxundo) {
        for (const Coin& coin : tx_undo.vprevout) {
            coins.push_back(coin);
        }
    }

    UtxoSetInclusionProof proof;
    if (!proof.ReconstructLeaves(active_chain, block.vtx, coins, in_skip)) {
        return error("%s could not create targets from transactions", __func__);
    }

    std::vector<utreexo::Hash> target_hashes;
    ComputeLeafHashes(proof.GetLeaves(), target_hashes);

    LOCK(m_forest_mutex);

    utreexo::BatchProof<utreexo::Hash> block_proof;
    if (!m_forest->Prove(block_proof, target_hashes)) {
        return error("%s failed to create proof for block %d", __func__, pindex->nHeight);
    }

    proof.SetProof(block_proof);

    size_t bytes_written = WriteProofToDisk(m_next_proof_pos, proof);
    if (bytes_written == 0) {
        return error("%s failed to write proof to disk for block %d", __func__, pindex->nHeight);
    }

    std::vector<UtreexoLeaf> new_leaves;
    GetNewLeavesFromBlock(block, pindex->nHeight, out_skip, new_leaves);

    std::vector<std::pair<std::array<uint8_t, 32>, bool>> leaves;
    for (const UtreexoLeaf& leaf_data : new_leaves) {
        CHashWriter writer(SER_GETHASH, PROTOCOL_VERSION);
        writer << leaf_data;
        leaves.emplace_back(writer.GetHash256(), true);
    }

    if (!m_forest->Modify(leaves, proof.GetProof().GetSortedTargets())) {
        return error("%s failed to modify the accumulator for block %d",
                     __func__, pindex->nHeight);
    }

    std::tuple<uint64_t, std::vector<utreexo::Hash>> forest_state{m_forest->GetState()};
    DBVal value{m_next_proof_pos, static_cast<int>(bytes_written), std::get<0>(forest_state), std::get<1>(forest_state)};
    std::pair<uint256, DBVal> val;
    val.first = pindex->GetBlockHash();
    val.second = value;
    if (!m_db->Write(DBHeightKey{pindex->nHeight}, val)) {
        return error("%s failed to write to the proof position to the db at height %d",
                     __func__, pindex->nHeight);
    }

    m_next_proof_pos.nPos += bytes_written;

    return true;
}

bool BlockProofIndex::Rewind(const CBlockIndex* current_tip,
                             const CBlockIndex* new_tip)
{
    // TODO support reorgs
    assert(false);
}

BaseIndex::DB& BlockProofIndex::GetDB() const { return *m_db; }

const char* BlockProofIndex::GetName() const { return BLOCK_PROOF_INDEX_NAME; }
