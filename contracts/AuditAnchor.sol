// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title AuditAnchor
/// @notice Write-once registry of Merkle roots that commit to batches of
///         OmniGuard-MCP audit records. Each batch covers a contiguous,
///         gap-free sequence range, and batches must be anchored in order.
///         There is deliberately no update or delete function: once a root is
///         anchored, a local rollback or forgery of the audit database can be
///         detected by anyone holding an RPC connection to this chain.
contract AuditAnchor {
    struct Anchor {
        bytes32 merkleRoot;
        uint64 startSeq;
        uint64 endSeq;
        uint64 timestamp;
        address submitter;
    }

    address public immutable owner;
    uint256 public batchCount;
    mapping(uint256 => Anchor) private anchors;
    mapping(address => bool) public isAnchorer;

    event BatchAnchored(
        uint256 indexed batchId,
        bytes32 merkleRoot,
        uint64 startSeq,
        uint64 endSeq,
        uint64 timestamp,
        address indexed submitter
    );
    event AnchorerSet(address indexed account, bool allowed);

    modifier onlyOwner() {
        require(msg.sender == owner, "AuditAnchor: not owner");
        _;
    }

    modifier onlyAnchorer() {
        require(isAnchorer[msg.sender], "AuditAnchor: not anchorer");
        _;
    }

    constructor() {
        owner = msg.sender;
        isAnchorer[msg.sender] = true;
        emit AnchorerSet(msg.sender, true);
    }

    function setAnchorer(address account, bool allowed) external onlyOwner {
        isAnchorer[account] = allowed;
        emit AnchorerSet(account, allowed);
    }

    /// @notice Anchor the Merkle root of audit records [startSeq, endSeq].
    function anchorBatch(
        uint256 batchId,
        bytes32 merkleRoot,
        uint64 startSeq,
        uint64 endSeq
    ) external onlyAnchorer {
        require(batchId == batchCount, "AuditAnchor: out-of-order batch");
        require(merkleRoot != bytes32(0), "AuditAnchor: empty root");
        require(endSeq >= startSeq, "AuditAnchor: bad range");
        if (batchId == 0) {
            require(startSeq == 1, "AuditAnchor: first batch must start at 1");
        } else {
            require(
                startSeq == anchors[batchId - 1].endSeq + 1,
                "AuditAnchor: sequence gap"
            );
        }
        anchors[batchId] = Anchor({
            merkleRoot: merkleRoot,
            startSeq: startSeq,
            endSeq: endSeq,
            timestamp: uint64(block.timestamp),
            submitter: msg.sender
        });
        batchCount = batchId + 1;
        emit BatchAnchored(batchId, merkleRoot, startSeq, endSeq, uint64(block.timestamp), msg.sender);
    }

    function getAnchor(uint256 batchId)
        external
        view
        returns (bytes32 merkleRoot, uint64 startSeq, uint64 endSeq, uint64 timestamp, address submitter)
    {
        require(batchId < batchCount, "AuditAnchor: unknown batch");
        Anchor storage a = anchors[batchId];
        return (a.merkleRoot, a.startSeq, a.endSeq, a.timestamp, a.submitter);
    }

    function verifyRoot(uint256 batchId, bytes32 merkleRoot) external view returns (bool) {
        return batchId < batchCount && anchors[batchId].merkleRoot == merkleRoot;
    }

    /// @notice Highest audit sequence number covered by any anchored batch (0 if none).
    function latestAnchoredSeq() external view returns (uint64) {
        if (batchCount == 0) {
            return 0;
        }
        return anchors[batchCount - 1].endSeq;
    }
}
