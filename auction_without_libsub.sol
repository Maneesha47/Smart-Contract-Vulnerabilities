
pragma solidity ^0.4.21;


interface IERC165 {

  /**
   * @notice Query if a contract implements an interface
   * @param interfaceId The interface identifier, as specified in ERC-165
   * @dev Interface identification is specified in ERC-165. This function
   * uses less than 30,000 gas.
   */
  function supportsInterface(bytes4 interfaceId)
    external
    view
    returns (bool);
}



/**
 * @title ERC721 Non-Fungible Token Standard basic interface
 * @dev see https://github.com/ethereum/EIPs/blob/master/EIPS/eip-721.md
 */
contract IERC721 is IERC165 {

  event Transfer(
    address indexed from,
    address indexed to,
    uint256 indexed tokenId
  );
  event Approval(
    address indexed owner,
    address indexed approved,
    uint256 indexed tokenId
  );
  event ApprovalForAll(
    address indexed owner,
    address indexed operator,
    bool approved
  );

  function balanceOf(address owner) public view returns (uint256 balance);
  function ownerOf(uint256 tokenId) public view returns (address owner);

  function approve(address to, uint256 tokenId) public;
  function getApproved(uint256 tokenId)
    public view returns (address operator);

  function setApprovalForAll(address operator, bool _approved) public;
  function isApprovedForAll(address owner, address operator)
    public view returns (bool);

  function transferFrom(address from, address to, uint256 tokenId) public;
  function safeTransferFrom(address from, address to, uint256 tokenId)
    public;

  function safeTransferFrom(
    address from,
    address to,
    uint256 tokenId,
    bytes memory data 
  )
    public;
}


//import "../../openzeppelin-solidity/contracts/token/ERC721/IERC721Receiver.sol";
/**
 * @title ERC721 token receiver interface
 * @dev Interface for any contract that wants to support safeTransfers
 * from ERC721 asset contracts.
 */
contract IERC721Receiver {
  /**
   * @notice Handle the receipt of an NFT
   * @dev The ERC721 smart contract calls this function on the recipient
   * after a `safeTransfer`. This function MUST return the function selector,
   * otherwise the caller will revert the transaction. The selector to be
   * returned can be obtained as `this.onERC721Received.selector`. This
   * function MAY throw to revert and reject the transfer.
   * Note: the ERC721 contract address is always the message sender.
   * @param operator The address which called `safeTransferFrom` function
   * @param from The address which previously owned the token
   * @param tokenId The NFT identifier which is being transferred
   * @param data Additional data with no specified format
   * @return `bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"))`
   */
  function onERC721Received(
    address operator,
    address from,
    uint256 tokenId,
    bytes memory data
  )
    public
    returns(bytes4);
}

contract ERC721Auction is IERC721Receiver {
  IERC721 public erc721;
  uint256 public erc721TokenId;

  address public seller;

  uint32 public startBlock;
  uint32 public endBlock;

  mapping (address => uint256) public bids;
  address public winningBidder;

  /// @notice This creates the auction.
  function onERC721Received(
    address _operator,
    address _from,
    uint256 _tokenId,
    bytes _data
  ) public returns(bytes4) {
    require(address(erc721) == 0x0);


    // In solidity 0.5.0, we can just do this:
    // (startBlock, endBlock) = abi.decode(_data, (uint32, uint32));
    // For now, here is some janky assembly hack that does the same thing,
    // only less efficiently.
    require(_data.length == 8);
    bytes memory data = _data; // Copy to memory;
    uint32 tempStartBlock;
    uint32 tempEndBlock;
    assembly {
      tempStartBlock := div(mload(add(data, 32)), exp(2, 224))
      tempEndBlock := and(div(mload(add(data, 32)), exp(2, 192)), 0xffffffff)
    }

    startBlock = tempStartBlock;
    endBlock = tempEndBlock;

    require(block.number < startBlock);
    require(startBlock < endBlock);
    erc721 = IERC721(msg.sender);
    erc721TokenId = _tokenId;
    seller = _from;

    return bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"));
  }

  function bid() payable external {
    require(address(erc721) != 0x0);
    require(startBlock <= block.number && block.number <= endBlock);
    bids[msg.sender] += msg.value;
    if (bids[msg.sender] > bids[winningBidder]) {
      winningBidder = msg.sender;
    }
  }

  function finalize() external {
    require(address(erc721) != 0x0);
    require(endBlock < block.number);
    uint256 bid = bids[msg.sender];
    bids[msg.sender] = 0;
    if (msg.sender == winningBidder) {
      erc721.safeTransferFrom(address(this), msg.sender, erc721TokenId);
      seller.transfer(bid);
    } else {
      msg.sender.transfer(bid);
    }
  }
}
