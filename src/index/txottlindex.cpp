#include <coins.h>
#include <index/txottlindex.h>
#include <undo.h>
#include <unordered_set>
#include <util/system.h>
#include <node/blockstorage.h>

std::unique_ptr<TxoTtlIndex> g_txottlindex;

constexpr char DB_TTLBLOCK_POS = 'P';
constexpr char DB_BLOCK_HEIGHT = 't';


constexpr unsigned int MAX_TTL_FILE_SIZE = 0x1000000; // 16 MiB
/** The pre-allocation chunk size for ttl?????.dat files */
constexpr unsigned int TTL_FILE_CHUNK_SIZE = 0x100000; // 1 MiB

struct DBVal {
    FlatFilePos pos;
    int size;

    SERIALIZE_METHODS(DBVal, obj) { READWRITE(obj.pos, obj.size); }
};

struct DBHeightKey {
    int height;

    DBHeightKey() : height(0) {}
    explicit DBHeightKey(int height_in) : height(height_in) {}

    template<typename Stream>
    void Serialize(Stream& s) const
    {
        ser_writedata8(s, DB_BLOCK_HEIGHT);
        ser_writedata32be(s, height);
    }

    template<typename Stream>
    void Unserialize(Stream& s)
    {
        char prefix = ser_readdata8(s);
        if (prefix != DB_BLOCK_HEIGHT) {
            throw std::ios_base::failure("Invalid format for ttl index DB height key");
        }
        height = ser_readdata32be(s);
    }
};

TxoTtlIndex::TxoTtlIndex(size_t n_cache_size, bool f_memory, bool f_wipe)
{
    fs::path path = gArgs.GetDataDirNet() / "indexes" / GetName();
    fs::create_directories(path);

    m_db = std::make_unique<BaseIndex::DB>(path / "db", n_cache_size, f_memory, f_wipe);
    m_ttlblock_fileseq = std::make_unique<FlatFileSeq>(std::move(path), "ttl", TTL_FILE_CHUNK_SIZE);
}

bool TxoTtlIndex::ReadRawTxoTtlBlockFromDisk(int height, std::vector<uint8_t>& raw_block) const
{
    DBVal val;
    if (!m_db->Read(DBHeightKey{height}, val)) return false;

    CAutoFile file(m_ttlblock_fileseq->Open(val.pos), SER_DISK, CLIENT_VERSION);
    raw_block.resize(val.size * 4);
    file.read((char*)raw_block.data(), raw_block.size());

    return true;
}

bool TxoTtlIndex::ReadTxoTtlBlockFromDisk(const int height, TxoTtlBlock& ttl_block) const
{
    std::vector<uint8_t> raw_block;
    if (!ReadRawTxoTtlBlockFromDisk(height, raw_block)) return false;

    ttl_block = TxoTtlBlock(height, raw_block);

    return true;
}

bool TxoTtlIndex::WriteTxoTtlBlockToDisk(const TxoTtlBlock& ttl_block)
{
    return ttl_block.ForEachHeight([this](int height, const std::vector<TxoTtl>& ttls) {
        DBVal val;
        if (!m_db->Read(DBHeightKey{height}, val)) return false;

        CAutoFile file(m_ttlblock_fileseq->Open(val.pos), SER_DISK, CLIENT_VERSION);
        std::vector<uint8_t> raw_block(val.size * 4);
        file.read((char*)raw_block.data(), raw_block.size());

        for (const TxoTtl& ttl : ttls) {
            WriteLE32(raw_block.data() + ttl.m_index * 4, ttl.m_value);
        }

        if (fseek(file.Get(), -raw_block.size(), SEEK_CUR)) return false;

        file.write((char*)raw_block.data(), raw_block.size());

        return true;
    });
}

size_t TxoTtlIndex::AllocateForNextTtlBlock(int n_ttls)
{
    size_t data_size = 4 * n_ttls;

    // If writing the ttls would overflow the file, flush and move to the next one.
    if (m_next_ttlblock_pos.nPos + data_size > MAX_TTL_FILE_SIZE) {
        CAutoFile last_file(m_ttlblock_fileseq->Open(m_next_ttlblock_pos), SER_DISK, CLIENT_VERSION);
        if (last_file.IsNull()) {
            LogPrintf("%s: Failed to open filter file %d\n", __func__, m_next_ttlblock_pos.nFile);
            return 0;
        }
        if (!TruncateFile(last_file.Get(), m_next_ttlblock_pos.nPos)) {
            LogPrintf("%s: Failed to truncate filter file %d\n", __func__, m_next_ttlblock_pos.nFile);
            return 0;
        }
        if (!FileCommit(last_file.Get())) {
            LogPrintf("%s: Failed to commit filter file %d\n", __func__, m_next_ttlblock_pos.nFile);
            return 0;
        }

        m_next_ttlblock_pos.nFile++;
        m_next_ttlblock_pos.nPos = 0;
    }

    // Pre-allocate sufficient space for filter data.
    bool out_of_space;
    m_ttlblock_fileseq->Allocate(m_next_ttlblock_pos, data_size, out_of_space);
    if (out_of_space) {
        LogPrintf("%s: out of disk space\n", __func__);
        return 0;
    }

    return data_size;
}

bool TxoTtlIndex::Init()
{
    if (!m_db->Read(DB_TTLBLOCK_POS, m_next_ttlblock_pos)) {
        // Check that the cause of the read failure is that the key does not exist. Any other errors
        // indicate database corruption or a disk failure, and starting the index would cause
        // further corruption.
        if (m_db->Exists(DB_TTLBLOCK_POS)) {
            return error("%s: Cannot read current %s state; index may be corrupted",
                         __func__, GetName());
        }

        // If the DB_TTLBLOCK_POS is not set, then initialize to the first location.
        m_next_ttlblock_pos.nFile = 0;
        m_next_ttlblock_pos.nPos = 0;
    }

    return BaseIndex::Init();
}

bool TxoTtlIndex::CommitInternal(CDBBatch& batch)
{
    // Flush current ttl file to disk.
    CAutoFile file(m_ttlblock_fileseq->Open(m_next_ttlblock_pos), SER_DISK, CLIENT_VERSION);
    if (file.IsNull()) {
        return error("%s: Failed to open filter file %d", __func__, m_next_ttlblock_pos.nFile);
    }
    if (!FileCommit(file.Get())) {
        return error("%s: Failed to commit filter file %d", __func__, m_next_ttlblock_pos.nFile);
    }

    batch.Write(DB_TTLBLOCK_POS, m_next_ttlblock_pos);

    return BaseIndex::CommitInternal(batch);
}

bool TxoTtlIndex::WriteBlock(const CBlock& block, const CBlockIndex* pindex)
{
    // Get the undo block. We need it to get the heights of the spend transaction outputs.
    CBlockUndo block_undo;
    if (pindex->nHeight > 0 && !UndoReadFromDisk(block_undo, pindex)) {
        return false;
    }

    // Collect all outpoints that survive this block to avoid same block spends.
    std::unordered_set<COutPoint, SaltedOutpointHasher> outpoints;
    for (const CTransactionRef& tx : block.vtx) {
        for (const CTxIn& txin : tx->vin) {
            outpoints.erase(txin.prevout);
        }

        for (uint32_t txout_index = 0; txout_index < tx->vout.size(); ++txout_index) {
            // Ignore unspendable outputs.
            if (tx->vout[txout_index].scriptPubKey.IsUnspendable()) continue;
            outpoints.insert(COutPoint{tx->GetHash(), txout_index});
        }
    }

    uint32_t ttl_index = 0;
    TxoTtlBlock ttl_block;
    for (auto tx_index = 0; tx_index < block.vtx.size(); ++tx_index) {
        const CTransactionRef& tx = block.vtx[tx_index];
        CDBBatch db_batch(*m_db);

        if (!tx->IsCoinBase()) {
            auto previous_outputs = block_undo.vtxundo.at(tx_index - 1).vprevout;
            for (auto txin_index = 0; txin_index < previous_outputs.size(); ++txin_index) {
                const Coin& coin = previous_outputs[txin_index];

                // Ignore same block spends.
                if (coin.nHeight == pindex->nHeight) continue;

                TxoTtl ttl;
                // Lookup up the block location of the stxo in the db.
                if (!m_db->Read(tx->vin.at(txin_index).prevout, ttl.m_index)) {
                    return error("%s: ttl index for outpoint(%s) did not exist", __func__, tx->vin.at(txin_index).prevout.ToString());
                }
                db_batch.Erase(tx->vin.at(txin_index).prevout);

                // Compute the live times of the stxo.
                ttl.m_value = pindex->nHeight - coin.nHeight;

                // Add the ttl to the ttl block map.
                ttl_block.GetTtls(coin.nHeight).push_back(ttl);
            }
        }

        // Add the block locations of the new utxos to the db.
        for (uint32_t txout_index = 0; txout_index < tx->vout.size(); ++txout_index) {
            auto outpoint = outpoints.find(COutPoint{tx->GetHash(), txout_index});
            if (outpoint != outpoints.end()) {
                db_batch.Write(*outpoint, ttl_index);
                ++ttl_index;
            }
        }

        if (!m_db->WriteBatch(db_batch)) return error("%s: could not write ttl index batch at height %d", __func__, pindex->nHeight);
    }

    // Write the ttls to disk. This is slow since a bunch of flatfiles are opened and written to
    // in order to fill in the now known ttl values.
    if (!WriteTxoTtlBlockToDisk(ttl_block)) return error("%s: could not write ttl block to disk at height %d", __func__, pindex->nHeight);

    size_t n_ttl_bytes = AllocateForNextTtlBlock(ttl_index);
    if (n_ttl_bytes == 0) return false;

    // Save the position of the ttl block in the index db.
    if (!m_db->Write(DBHeightKey{pindex->nHeight}, DBVal{m_next_ttlblock_pos, static_cast<int>(ttl_index)})) {
        return false;
    }

    m_next_ttlblock_pos.nPos += n_ttl_bytes;
    return true;
}

bool TxoTtlIndex::Rewind(const CBlockIndex* current_tip, const CBlockIndex* new_tip)
{
    // TODO:this will cause ttls blocks to be overwritten, maybe do what the block filter index does?
    DBVal val;
    if (!m_db->Read(DBHeightKey{new_tip->nHeight}, val)) {
        return false;
    }

    if (!m_db->Write(DB_TTLBLOCK_POS, val.pos)) {
        return false;
    }

    m_next_ttlblock_pos = val.pos;

    return BaseIndex::Rewind(current_tip, new_tip);
}

BaseIndex::DB& TxoTtlIndex::GetDB() const { return *m_db; }

bool TxoTtlIndex::LookupTtlBlocks(int start_height, CBlockIndex& stop_index, std::vector<TxoTtlBlock>& ttl_blocks) const
{
    ttl_blocks.reserve(stop_index.nHeight - start_height);

    for (; start_height < stop_index.nHeight; ++start_height) {
        TxoTtlBlock ttl_block;
        if (!ReadTxoTtlBlockFromDisk(start_height, ttl_block)) {
            return false;
        }

        ttl_blocks.push_back(ttl_block);
    }

    return true;
}
