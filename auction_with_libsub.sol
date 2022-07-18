
pragma solidity >=0.4.18;


library SafeMath {

  /**
  * @dev Multiplies two numbers, reverts on overflow.
  */
  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    // Gas optimization: this is cheaper than requiring 'a' not being zero, but the
    // benefit is lost if 'b' is also tested.
    // See: https://github.com/OpenZeppelin/openzeppelin-solidity/pull/522
    if (a == 0) {
      return 0;
    }

    uint256 c = a * b;
    require(c / a == b);

    return c;
  }

  /**
  * @dev Integer division of two numbers truncating the quotient, reverts on division by zero.
  */
  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    require(b > 0); // Solidity only automatically asserts when dividing by 0
    uint256 c = a / b;
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold

    return c;
  }

  /**
  * @dev Subtracts two numbers, reverts on overflow (i.e. if subtrahend is greater than minuend).
  */
  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    require(b <= a);
    uint256 c = a - b;

    return c;
  }

  /**
  * @dev Adds two numbers, reverts on overflow.
  */
  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    require(c >= a);

    return c;
  }

  /**
  * @dev Divides two numbers and returns the remainder (unsigned integer modulo),
  * reverts when dividing by zero.
  */
  function mod(uint256 a, uint256 b) internal pure returns (uint256) {
    require(b != 0);
    return a % b;
  }
}

library RLP {

 uint constant DATA_SHORT_START = 0x80;
 uint constant DATA_LONG_START = 0xB8;
 uint constant LIST_SHORT_START = 0xC0;
 uint constant LIST_LONG_START = 0xF8;

 uint constant DATA_LONG_OFFSET = 0xB7;
 uint constant LIST_LONG_OFFSET = 0xF7;


 struct RLPItem {
     uint _unsafe_memPtr;    // Pointer to the RLP-encoded bytes.
     uint _unsafe_length;    // Number of bytes. This is the full length of the string.
 }

 struct Iterator {
     RLPItem _unsafe_item;   // Item that's being iterated over.
     uint _unsafe_nextPtr;   // Position of the next item in the list.
 }

 /* Iterator */

 function next(Iterator memory self) internal view returns (RLPItem memory subItem) {
     if(hasNext(self)) {
         var ptr = self._unsafe_nextPtr;
         var itemLength = _itemLength(ptr);
         subItem._unsafe_memPtr = ptr;
         subItem._unsafe_length = itemLength;
         self._unsafe_nextPtr = ptr + itemLength;
     }
     else
         revert();
 }

 function next(Iterator memory self, bool strict) internal view returns (RLPItem memory subItem) {
     subItem = next(self);
     if(strict && !_validate(subItem))
         revert();
     return;
 }

 function hasNext(Iterator memory self) internal view returns (bool) {
     var item = self._unsafe_item;
     return self._unsafe_nextPtr < item._unsafe_memPtr + item._unsafe_length;
 }

 /* RLPItem */

 /// @dev Creates an RLPItem from an array of RLP encoded bytes.
 /// @param self The RLP encoded bytes.
 /// @return An RLPItem
 function toRLPItem(bytes memory self) internal view returns (RLPItem memory) {
     uint len = self.length;
     if (len == 0) {
         return RLPItem(0, 0);
     }
     uint memPtr;
     assembly {
         memPtr := add(self, 0x20)
     }
     return RLPItem(memPtr, len);
 }

 /// @dev Creates an RLPItem from an array of RLP encoded bytes.
 /// @param self The RLP encoded bytes.
 /// @param strict Will revert() if the data is not RLP encoded.
 /// @return An RLPItem
 function toRLPItem(bytes memory self, bool strict) internal view returns (RLPItem memory) {
     var item = toRLPItem(self);
     if(strict) {
         uint len = self.length;
         if(_payloadOffset(item) > len)
             revert();
         if(_itemLength(item._unsafe_memPtr) != len)
             revert();
         if(!_validate(item))
             revert();
     }
     return item;
 }

 /// @dev Check if the RLP item is null.
 /// @param self The RLP item.
 /// @return 'true' if the item is null.
 function isNull(RLPItem memory self) internal view returns (bool ret) {
     return self._unsafe_length == 0;
 }

 /// @dev Check if the RLP item is a list.
 /// @param self The RLP item.
 /// @return 'true' if the item is a list.
 function isList(RLPItem memory self) internal view returns (bool ret) {
     if (self._unsafe_length == 0)
         return false;
     uint memPtr = self._unsafe_memPtr;
     assembly {
         ret := iszero(lt(byte(0, mload(memPtr)), 0xC0))
     }
 }

 /// @dev Check if the RLP item is data.
 /// @param self The RLP item.
 /// @return 'true' if the item is data.
 function isData(RLPItem memory self) internal view returns (bool ret) {
     if (self._unsafe_length == 0)
         return false;
     uint memPtr = self._unsafe_memPtr;
     assembly {
         ret := lt(byte(0, mload(memPtr)), 0xC0)
     }
 }

 /// @dev Check if the RLP item is empty (string or list).
 /// @param self The RLP item.
 /// @return 'true' if the item is null.
 function isEmpty(RLPItem memory self) internal view returns (bool ret) {
     if(isNull(self))
         return false;
     uint b0;
     uint memPtr = self._unsafe_memPtr;
     assembly {
         b0 := byte(0, mload(memPtr))
     }
     return (b0 == DATA_SHORT_START || b0 == LIST_SHORT_START);
 }

 /// @dev Get the number of items in an RLP encoded list.
 /// @param self The RLP item.
 /// @return The number of items.
 function items(RLPItem memory self) internal view returns (uint) {
     if (!isList(self))
         return 0;
     uint b0;
     uint memPtr = self._unsafe_memPtr;
     assembly {
         b0 := byte(0, mload(memPtr))
     }
     uint pos = memPtr + _payloadOffset(self);
     uint last = memPtr + self._unsafe_length - 1;
     uint itms;
     while(pos <= last) {
         pos += _itemLength(pos);
         itms++;
     }
     return itms;
 }

 /// @dev Create an iterator.
 /// @param self The RLP item.
 /// @return An 'Iterator' over the item.
 function iterator(RLPItem memory self) internal view returns (Iterator memory it) {
     if (!isList(self))
         revert();
     uint ptr = self._unsafe_memPtr + _payloadOffset(self);
     it._unsafe_item = self;
     it._unsafe_nextPtr = ptr;
 }

 /// @dev Return the RLP encoded bytes.
 /// @param self The RLPItem.
 /// @return The bytes.
 function toBytes(RLPItem memory self) internal view returns (bytes memory bts) {
     var len = self._unsafe_length;
     if (len == 0)
         return;
     bts = new bytes(len);
     _copyToBytes(self._unsafe_memPtr, bts, len);
 }

 /// @dev Decode an RLPItem into bytes. This will not work if the
 /// RLPItem is a list.
 /// @param self The RLPItem.
 /// @return The decoded string.
 function toData(RLPItem memory self) internal view returns (bytes memory bts) {
     if(!isData(self))
         revert();
     var (rStartPos, len) = _decode(self);
     bts = new bytes(len);
     _copyToBytes(rStartPos, bts, len);
 }

 /// @dev Get the list of sub-items from an RLP encoded list.
 /// Warning: This is inefficient, as it requires that the list is read twice.
 /// @param self The RLP item.
 /// @return Array of RLPItems.
 function toList(RLPItem memory self) internal view returns (RLPItem[] memory list) {
     if(!isList(self))
         revert();
     var numItems = items(self);
     list = new RLPItem[](numItems);
     var it = iterator(self);
     uint idx;
     while(hasNext(it)) {
         list[idx] = next(it);
         idx++;
     }
 }

 /// @dev Decode an RLPItem into an ascii string. This will not work if the
 /// RLPItem is a list.
 /// @param self The RLPItem.
 /// @return The decoded string.
 function toAscii(RLPItem memory self) internal view returns (string memory str) {
     if(!isData(self))
         revert();
     var (rStartPos, len) = _decode(self);
     bytes memory bts = new bytes(len);
     _copyToBytes(rStartPos, bts, len);
     str = string(bts);
 }

 /// @dev Decode an RLPItem into a uint. This will not work if the
 /// RLPItem is a list.
 /// @param self The RLPItem.
 /// @return The decoded string.
 function toUint(RLPItem memory self) internal view returns (uint data) {
     if(!isData(self))
         revert();
     var (rStartPos, len) = _decode(self);
     if (len > 32)
         revert();
     if (len == 0)
         return 0;
     assembly {
         data := div(mload(rStartPos), exp(256, sub(32, len)))
     }
 }

 /// @dev Decode an RLPItem into a boolean. This will not work if the
 /// RLPItem is a list.
 /// @param self The RLPItem.
 /// @return The decoded string.
 function toBool(RLPItem memory self) internal view returns (bool data) {
     if(!isData(self))
         revert();
     var (rStartPos, len) = _decode(self);
     if (len != 1)
         revert();
     uint temp;
     assembly {
         temp := byte(0, mload(rStartPos))
     }
     if (temp > 1)
         revert();
     return temp == 1 ? true : false;
 }

 /// @dev Decode an RLPItem into a byte. This will not work if the
 /// RLPItem is a list.
 /// @param self The RLPItem.
 /// @return The decoded string.
 function toByte(RLPItem memory self) internal view returns (byte data) {
     if(!isData(self))
         revert();
     var (rStartPos, len) = _decode(self);
     if (len != 1)
         revert();
     uint temp;
     assembly {
         temp := byte(0, mload(rStartPos))
     }
     return byte(temp);
 }

 /// @dev Decode an RLPItem into an int. This will not work if the
 /// RLPItem is a list.
 /// @param self The RLPItem.
 /// @return The decoded string.
 function toInt(RLPItem memory self) internal view returns (int data) {
     return int(toUint(self));
 }

 /// @dev Decode an RLPItem into a bytes32. This will not work if the
 /// RLPItem is a list.
 /// @param self The RLPItem.
 /// @return The decoded string.
 function toBytes32(RLPItem memory self) internal view returns (bytes32 data) {
     return bytes32(toUint(self));
 }

 /// @dev Decode an RLPItem into an address. This will not work if the
 /// RLPItem is a list.
 /// @param self The RLPItem.
 /// @return The decoded string.
 function toAddress(RLPItem memory self) internal view returns (address data) {
     if(!isData(self))
         revert();
     var (rStartPos, len) = _decode(self);
     if (len != 20)
         revert();
     assembly {
         data := div(mload(rStartPos), exp(256, 12))
     }
 }

 // Get the payload offset.
 function _payloadOffset(RLPItem memory self) private view returns (uint) {
     if(self._unsafe_length == 0)
         return 0;
     uint b0;
     uint memPtr = self._unsafe_memPtr;
     assembly {
         b0 := byte(0, mload(memPtr))
     }
     if(b0 < DATA_SHORT_START)
         return 0;
     if(b0 < DATA_LONG_START || (b0 >= LIST_SHORT_START && b0 < LIST_LONG_START))
         return 1;
     if(b0 < LIST_SHORT_START)
         return b0 - DATA_LONG_OFFSET + 1;
     return b0 - LIST_LONG_OFFSET + 1;
 }

 // Get the full length of an RLP item.
 function _itemLength(uint memPtr) private view returns (uint len) {
     uint b0;
     assembly {
         b0 := byte(0, mload(memPtr))
     }
     if (b0 < DATA_SHORT_START)
         len = 1;
     else if (b0 < DATA_LONG_START)
         len = b0 - DATA_SHORT_START + 1;
     else if (b0 < LIST_SHORT_START) {
         assembly {
             let bLen := sub(b0, 0xB7) // bytes length (DATA_LONG_OFFSET)
             let dLen := div(mload(add(memPtr, 1)), exp(256, sub(32, bLen))) // data length
             len := add(1, add(bLen, dLen)) // total length
         }
     }
     else if (b0 < LIST_LONG_START)
         len = b0 - LIST_SHORT_START + 1;
     else {
         assembly {
             let bLen := sub(b0, 0xF7) // bytes length (LIST_LONG_OFFSET)
             let dLen := div(mload(add(memPtr, 1)), exp(256, sub(32, bLen))) // data length
             len := add(1, add(bLen, dLen)) // total length
         }
     }
 }

 // Get start position and length of the data.
 function _decode(RLPItem memory self) private view returns (uint memPtr, uint len) {
     if(!isData(self))
         revert();
     uint b0;
     uint start = self._unsafe_memPtr;
     assembly {
         b0 := byte(0, mload(start))
     }
     if (b0 < DATA_SHORT_START) {
         memPtr = start;
         len = 1;
         return;
     }
     if (b0 < DATA_LONG_START) {
         len = self._unsafe_length - 1;
         memPtr = start + 1;
     } else {
         uint bLen;
         assembly {
             bLen := sub(b0, 0xB7) // DATA_LONG_OFFSET
         }
         len = self._unsafe_length - 1 - bLen;
         memPtr = start + bLen + 1;
     }
     return;
 }

 // Assumes that enough memory has been allocated to store in target.
 function _copyToBytes(uint btsPtr, bytes memory tgt, uint btsLen) private view {
     // Exploiting the fact that 'tgt' was the last thing to be allocated,
     // we can write entire words, and just overwrite any excess.
     assembly {
         {
                 let i := 0 // Start at arr + 0x20
                 let words := div(add(btsLen, 31), 32)
                 let rOffset := btsPtr
                 let wOffset := add(tgt, 0x20)
             tag_loop:
                 jumpi(end, eq(i, words))
                 {
                     let offset := mul(i, 0x20)
                     mstore(add(wOffset, offset), mload(add(rOffset, offset)))
                     i := add(i, 1)
                 }
                 jump(tag_loop)
             end:
                 mstore(add(tgt, add(0x20, mload(tgt))), 0)
         }
     }
 }

     // Check that an RLP item is valid.
     function _validate(RLPItem memory self) private view returns (bool ret) {
         // Check that RLP is well-formed.
         uint b0;
         uint b1;
         uint memPtr = self._unsafe_memPtr;
         assembly {
             b0 := byte(0, mload(memPtr))
             b1 := byte(1, mload(memPtr))
         }
         if(b0 == DATA_SHORT_START + 1 && b1 < DATA_SHORT_START)
             return false;
         return true;
     }
}

contract ProvethVerifier {
    using RLP for RLP.RLPItem;
    using RLP for RLP.Iterator;
    using RLP for bytes;

    uint256 constant TX_ROOT_HASH_INDEX = 4;

    struct UnsignedTransaction {
        uint256 nonce;
        uint256 gasprice;
        uint256 startgas;
        address to;
        uint256 value;
        bytes data;
        bool isContractCreation;
    }

    struct SignedTransaction {
        uint256 nonce;
        uint256 gasprice;
        uint256 startgas;
        address to;
        uint256 value;
        bytes data;
        uint256 v;
        uint256 r;
        uint256 s;
        bool isContractCreation;
    }

    function decodeUnsignedTx(bytes memory rlpUnsignedTx) internal view returns (UnsignedTransaction memory t) {
        RLP.RLPItem[] memory fields = rlpUnsignedTx.toRLPItem().toList();
        require(fields.length == 6);
        address potentialAddress;
        bool isContractCreation;
        if(fields[3].isEmpty()) {
            potentialAddress = 0x0000000000000000000000000000000000000000;
            isContractCreation = true;
        } else {
            potentialAddress = fields[3].toAddress();
            isContractCreation = false;
        }
        t = UnsignedTransaction(
            fields[0].toUint(), // nonce
            fields[1].toUint(), // gasprice
            fields[2].toUint(), // startgas
            potentialAddress,   // to
            fields[4].toUint(), // value
            fields[5].toData(), // data
            isContractCreation
        );
    }

    // TODO(lorenzb): This should actually be pure, not view. Probably because
    // wrong declarations in RLP.sol.
    function decodeSignedTx(bytes memory rlpSignedTx) internal view returns (SignedTransaction memory t) {
        RLP.RLPItem[] memory fields = rlpSignedTx.toRLPItem().toList();
        address potentialAddress;
        bool isContractCreation;
        if(fields[3].isEmpty()) {
            potentialAddress = 0x0000000000000000000000000000000000000000;
            isContractCreation = true;
        } else {
            potentialAddress = fields[3].toAddress();
            isContractCreation = false;
        }
        t = SignedTransaction(
            fields[0].toUint(),
            fields[1].toUint(),
            fields[2].toUint(),
            potentialAddress,
            fields[4].toUint(),
            fields[5].toData(),
            fields[6].toUint(),
            fields[7].toUint(),
            fields[8].toUint(),
            isContractCreation
        );
    }

    function decodeNibbles(bytes memory compact, uint skipNibbles) internal pure returns (bytes  memory nibbles) {
        require(compact.length > 0);

        uint length = compact.length * 2;
        require(skipNibbles <= length);
        length -= skipNibbles;

        nibbles = new bytes(length);
        uint nibblesLength = 0;

        for (uint i = skipNibbles; i < skipNibbles + length; i += 1) {
            if (i % 2 == 0) {
                nibbles[nibblesLength] = bytes1((uint8(compact[i/2]) >> 4) & 0xF);
            } else {
                nibbles[nibblesLength] = bytes1((uint8(compact[i/2]) >> 0) & 0xF);
            }
            nibblesLength += 1;
        }

        assert(nibblesLength == nibbles.length);
    }

    function merklePatriciaCompactDecode(bytes memory compact) internal pure returns (bytes  memory nibbles) {
        require(compact.length > 0);
        uint first_nibble = uint8(compact[0]) >> 4 & 0xF;
        uint skipNibbles;
        if (first_nibble == 0) {
            skipNibbles = 2;
        } else if (first_nibble == 1) {
            skipNibbles = 1;
        } else if (first_nibble == 2) {
            skipNibbles = 2;
        } else if (first_nibble == 3) {
            skipNibbles = 1;
        } else {
            // Not supposed to happen!
            revert();
        }
        return decodeNibbles(compact, skipNibbles);
    }

    function isPrefix(bytes memory prefix, bytes memory full) internal pure returns (bool) {
        if (prefix.length > full.length) {
            return false;
        }

        for (uint i = 0; i < prefix.length; i += 1) {
            if (prefix[i] != full[i]) {
                return false;
            }
        }

        return true;
    }

    function sharedPrefixLength(uint xsOffset, bytes memory xs, bytes memory ys) internal pure returns (uint) {
    	uint i;
        for (i = 0; i + xsOffset < xs.length && i < ys.length; i++) {
            if (xs[i + xsOffset] != ys[i]) {
                return i;
            }
        }
        return i;
    }

    struct Proof {
        uint256 kind;
        bytes rlpBlockHeader;
        bytes32 txRootHash;
        bytes rlpTxIndex;
        uint txIndex;
        bytes mptPath;
        bytes stackIndexes;
        RLP.RLPItem[] stack;
    }

    function decodeProofBlob(bytes memory proofBlob) internal view returns (Proof memory proof) {
        RLP.RLPItem[] memory proofFields = proofBlob.toRLPItem().toList();
        proof = Proof(
            proofFields[0].toUint(),
            proofFields[1].toBytes(),
            proofFields[1].toList()[TX_ROOT_HASH_INDEX].toBytes32(),
            proofFields[2].toBytes(),
            proofFields[2].toUint(),
            proofFields[3].toData(),
            proofFields[4].toData(),
            proofFields[5].toList()
        );
    }

    uint8 constant public TX_PROOF_RESULT_PRESENT = 1;
    uint8 constant public TX_PROOF_RESULT_ABSENT = 2;

    function txProof(
        bytes32 blockHash,
        bytes memory proofBlob
    ) public returns (
        uint8 result, // see TX_PROOF_RESULT_*
        uint256 index,
        uint256 nonce,
        uint256 gasprice,
        uint256 startgas,
        address to, // 20 byte address for "regular" tx,
                  // empty for contract creation tx
        uint256 value,
        bytes memory data,
        uint256 v,
        uint256 r,
        uint256 s,
        bool isContractCreation
    ) {
        SignedTransaction memory t;
        (result, index, t) = validateTxProof(blockHash, proofBlob);
        nonce = t.nonce;
        gasprice = t.gasprice;
        startgas = t.startgas;
        to = t.to;
        value = t.value;
        data = t.data;
        v = t.v;
        r = t.r;
        s = t.s;
        isContractCreation = t.isContractCreation;
    }

    function validateTxProof(
        bytes32 blockHash,
        bytes memory proofBlob
    ) internal returns (uint8 result, uint256 index, SignedTransaction memory t) {
        result = 0;
        index = 0;
        Proof memory proof = decodeProofBlob(proofBlob);
        require(proof.stack.length == proof.stackIndexes.length);
        if (proof.kind != 1) {
            revert();
        }

        if (keccak256(proof.rlpBlockHeader) != blockHash) {
            revert();
        }

        bytes memory rlpTx = validateMPTProof(proof.txRootHash, proof.mptPath, proof.stackIndexes, proof.stack);

        bytes memory mptKeyNibbles = decodeNibbles(proof.rlpTxIndex, 0);
        if (rlpTx.length == 0) {
            // empty node
            if (isPrefix(proof.mptPath, mptKeyNibbles)) {
                result = TX_PROOF_RESULT_ABSENT;
                index = proof.txIndex;
                return;
            } else {
                revert();
            }
        } else {
            // tx
            if (isPrefix(proof.mptPath, mptKeyNibbles) && proof.mptPath.length == mptKeyNibbles.length) {
                result = TX_PROOF_RESULT_PRESENT;
                index = proof.txIndex;
                t  = decodeSignedTx(rlpTx);
                return;
            } else {
                revert();
            }
        }
    }

    function mptHashHash(bytes memory input) internal pure returns (bytes32) {
        if (input.length < 32) {
            return keccak256(input);
        } else {
            return keccak256(keccak256(input));
            
        }
    }

    function validateMPTProof(
        bytes32 rootHash,
        bytes memory mptPath,
        bytes memory stackIndexes,
        RLP.RLPItem[] memory stack
    ) internal returns (bytes memory value) {
        require(stackIndexes.length == stack.length);

        uint mptPathOffset = 0;

        bytes32 nodeHashHash;
        bytes memory rlpNode;
        RLP.RLPItem[] memory node;

        RLP.RLPItem memory rlpValue;

        if (stack.length == 0) {
            // Root hash of empty tx trie
            require(rootHash == 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421);
            return new bytes(0);
        }

        for (uint i = 0; i < stack.length; i++) {

            // We use the fact that an rlp encoded list consists of some
            // encoding of its length plus the concatenation of its
            // *rlp-encoded* items.
            rlpNode = stack[i].toBytes();
            if (i == 0 && rootHash != keccak256(rlpNode)) {
                revert();
            }
            if (i != 0 && nodeHashHash != mptHashHash(rlpNode)) {
                revert();
            }
            node = stack[i].toList();

            if (node.length == 2) {
                // Extension or Leaf node
                bytes memory nodePath = merklePatriciaCompactDecode(node[0].toData());

                uint prefixLength = sharedPrefixLength(mptPathOffset, mptPath, nodePath);
                mptPathOffset += prefixLength;

                if (stackIndexes[i] == 0xff) {
                    // proof claims divergent extension or leaf

                    if (i < stack.length - 1) {
                        // divergent node must come last in proof
                        revert();
                    }

                    if (prefixLength == nodePath.length) {
                        // node isn't divergent
                        revert();
                    }

                    if (mptPathOffset != mptPath.length) {
                        // didn't consume entire mptPath
                        revert();
                    }

                    return new bytes(0);
                } else if (stackIndexes[i] == 1) {
                    if (prefixLength != nodePath.length) {
                        // node is divergent
                        revert();
                    }

                    if (i < stack.length - 1) {
                        // not last level
                        if (node[uint(stackIndexes[i])].isData()) {
                            nodeHashHash = keccak256(node[uint(stackIndexes[i])].toData());
                        } else {
                            nodeHashHash = keccak256(node[uint(stackIndexes[i])].toBytes());
                        }
                    } else {
                        // didn't consume entire mptPath
                        if (mptPathOffset != mptPath.length) {
                            revert();
                        }

                        rlpValue = node[uint(stackIndexes[i])];
                        return rlpValue.toData();
                    }
                } else {
                    // an extension/leaf node only has two fields.
                    revert();
                }
            } else if (node.length == 17) {
                // Branch node
                if (stackIndexes[i] < 16) {
                    // advance mptPathOffset
                    if (mptPathOffset >= mptPath.length || mptPath[mptPathOffset] != stackIndexes[i]) {
                        revert();
                    }
                    mptPathOffset += 1;

                    if (i < stack.length - 1) {
                        // not last level
                        if (node[uint(stackIndexes[i])].isData()) {
                            nodeHashHash = keccak256(node[uint(stackIndexes[i])].toData());
                        } else {
                            nodeHashHash = keccak256(node[uint(stackIndexes[i])].toBytes());
                        }
                    } else {
                        // last level
                        // must have an empty hash, everything else is invalid
                        if (node[uint(stackIndexes[i])].toData().length != 0) {
                            revert();
                        }

                        if (mptPathOffset != mptPath.length) {
                            // didn't consume entire mptPath
                            revert();
                        }

                        return new bytes(0);
                    }
                } else if (stackIndexes[i] == 16) { // we want the value stored in this node
                    if (i < stack.length - 1) {
                        // value must come last in proof
                        revert();
                    }

                    if (mptPathOffset != mptPath.length) {
                        // didn't consume entire mptPath
                        revert();
                    }

                    rlpValue = node[uint(stackIndexes[i])];
                    return rlpValue.toData();
                } else {
                    revert();
                }
            } else {
                revert(); // This should never happen as we have
                          // already authenticated node at this point.
            }
        }

        // We should never reach this point.
        revert();
    }
}

contract LibSubmarineSimple is ProvethVerifier {

    using SafeMath for uint256;

    ////////////
    // Events //
    ////////////

    event Unlocked(
        bytes32 indexed _submarineId,
        uint96 _commitValue
    );
    event Revealed(
        bytes32 indexed _submarineId,
        uint96 _commitValue,
        bytes32 _witness,
        bytes32 _commitBlockHash,
        address _submarineAddr
    );

    /////////////
    // Storage //
    /////////////

    // the ECDSA v parameter: 27 allows us to be broadcast on any network (i.e.
    // mainnet, ropsten, rinkeby etc.)
    uint8 public vee = 27;
    // How many blocks must a submarine be committed for before being revealed.
    // For now, we choose a default of 20. Since a contract cannot look back
    // further than 256 blocks (limit comes from EVM BLOCKHASH opcode), we use a
    // uint8.
    uint8 public commitPeriodLength = 20;

    // Stored "session" state information
    mapping(bytes32 => SubmarineSession) public sessions;

    // A submarine send is considered "finished" when the amount revealed and
    // unlocked are both greater than zero, and the amount for the unlock is
    // greater than or equal to the reveal amount.
    struct SubmarineSession {
        // Amount the reveal transaction revealed would be sent in wei. When
        // greater than zero, the submarine has been revealed. A uint96 is large
        // enough to store the entire Ethereum supply (~ 1e26 Wei) 700 times
        // over.
        uint96 amountRevealed;
        // Amount the unlock transaction recieved in wei. When greater than
        // zero, the submarine has been unlocked; however the submarine may not
        // be finished, until the unlock amount is GREATER than the promised
        // revealed amount.
        uint96 amountUnlocked;
        // Block number of block containing commit transaction.
        uint32 commitTxBlockNumber;
        // Index of commit transaction within its block.
        uint16 commitTxIndex;
    }

    /////////////
    // Getters //
    /////////////

    /*
       Keeping these functions makes instantiating a contract more expensive for gas costs, but helps with testing
    */

    /**
     * @notice Helper function to return a submarine ID for associated given
     *         input data
     * @param _user address of the user that initiated the full submarine flow
     * @param _libsubmarine address of submarine contract. Usually address(this)
     * @param _commitValue amount of ether supposed to be sent in this submarine
     *        commit
     * @param _embeddedDAppData  optional Data passed embedded within the unlock
     *        tx. Clients can put whatever data they want committed to for their
     *        specific use case
     * @param _witness random commit secret data
     * @param _gasPrice the gas price that will be paid in the unlock tx
     * @param _gasLimit the gas limit that will be set in the unlock tx
     */
    function getSubmarineId(
        address _user,
        address _libsubmarine,
        uint256 _commitValue,
        bytes memory _embeddedDAppData,
        bytes32 _witness,
        uint256 _gasPrice,
        uint256 _gasLimit
    ) public pure returns (bytes32) {
        return keccak256(
            _user,
            _libsubmarine,
            _commitValue,
            _embeddedDAppData,
            _witness,
            _gasPrice,
            _gasLimit
        );
    }

    /**
     * @notice Return the session information associated with a submarine ID.
     * @return amountRevealed amount promised by user to be unlocked in reveal
     * @return amountUnlocked amount actually unlocked by the user at this time
     * @return commitTxBlockNumber block number that the user proved holds the
     *         commit TX.
     * @return commitTxIndex the index in the block where the commit tx is.
     */
    function getSubmarineState(bytes32 _submarineId) public view returns (
        uint96 amountRevealed,
        uint96 amountUnlocked,
        uint32 commitTxBlockNumber,
        uint16 commitTxIndex
    ) {
        SubmarineSession memory sesh = sessions[_submarineId];
        return (
            sesh.amountRevealed,
            sesh.amountUnlocked,
            sesh.commitTxBlockNumber,
            sesh.commitTxIndex
        );
    }

   /**
     * @notice Singleton session getter - amount of money sent in submarine send
     * @return amountRevealed amount promised by user to be unlocked in reveal
     */
    function getSubmarineAmount(bytes32 _submarineId) public view returns (
        uint96 amount
    ) {
        SubmarineSession memory sesh = sessions[_submarineId];
        return sesh.amountRevealed;
    }

    /**
     * @notice Singleton session getter - Commit TX Block number
     * @return commitTxBlockNumber block number that the user proved holds the
     *         commit TX.
     */
    function getSubmarineCommitBlockNumber(bytes32 _submarineId)
        public view returns (uint32 commitTxBlockNumber)
    {
        SubmarineSession memory sesh = sessions[_submarineId];
        return sesh.commitTxBlockNumber;
    }

    /**
     * @notice Singleton session getter - Commit TX Block index inside block
     * @return commitTxIndex the index in the block where the commit tx is.
     */
    function getSubmarineCommitTxIndex(bytes32 _submarineId)
        public view returns(uint16 commitTxIndex)
    {
        SubmarineSession memory sesh = sessions[_submarineId];
        return sesh.commitTxIndex;
    }

    /////////////
    // Setters //
    /////////////

    /**
     * @notice Consumers of this library should implement their custom reveal
     *         logic by overriding this method. This function is a handler that
     *         is called by reveal. A user calls reveal, LibSubmarine does the
     *         required submarine specific stuff, and then calls this handler
     *         for client specific implementation/handling.
     * @param  _submarineId the ID for this submarine workflow
     * @param _embeddedDAppData optional Data passed embedded within the unlock
     *        tx. Clients can put whatever data they want committed to for their
     *        specific use case
     * @param _value amount of ether revealed
     *
     */
    function onSubmarineReveal(
        bytes32 _submarineId,
        bytes memory _embeddedDAppData,
        uint256 _value
    ) internal;

    /**
     * @notice Function called by the user to reveal the session.
     * @dev warning Must be called within 256 blocks of the commit transaction
     *      to obtain the correct blockhash.
     * @param _commitTxBlockNumber Number of block in which the commit tx was
     *        included.
     * @param _embeddedDAppData optional Data passed embedded within the unlock
     * tx. This should probably be null
     * @param _witness Witness "secret" we committed to
     * @param _rlpUnlockTxUnsigned RLP encoded unsigned unlock transaction
     * @param _proofBlob the proof blob that gets passed to proveth to verify
     *        merkle trie inclusion in a prior block.
     */
    function reveal(
        uint32 _commitTxBlockNumber,
        bytes memory _embeddedDAppData,
        bytes32 _witness,
        bytes memory _rlpUnlockTxUnsigned,
        bytes memory _proofBlob
    ) public {
        bytes32 commitBlockHash = block.blockhash(_commitTxBlockNumber);
        require(
            commitBlockHash != 0x0
        );
        require(
            block.number.sub(_commitTxBlockNumber) > commitPeriodLength);

        UnsignedTransaction memory unsignedUnlockTx =
            decodeUnsignedTx(_rlpUnlockTxUnsigned);
        bytes32 unsignedUnlockTxHash = keccak256(_rlpUnlockTxUnsigned);

        require(unsignedUnlockTx.nonce == 0);
        require(unsignedUnlockTx.to == address(this));

        // fullCommit = (addressA + addressC + aux(sendAmount) + dappData + w + aux(gasPrice) + aux(gasLimit))
        bytes32 submarineId = getSubmarineId(
            msg.sender,
            address(this),
            unsignedUnlockTx.value,
            _embeddedDAppData,
            _witness,
            unsignedUnlockTx.gasprice,
            unsignedUnlockTx.startgas
        );

        require(
            sessions[submarineId].commitTxBlockNumber == 0
            
        );

        SignedTransaction memory provenCommitTx;
        uint8 provenCommitTxResultValid;
        uint256 provenCommitTxIndex;
        (
            provenCommitTxResultValid,
            provenCommitTxIndex,
            provenCommitTx.nonce,
            /* gasprice */,
            /* startgas */,
            provenCommitTx.to,
            provenCommitTx.value,
            provenCommitTx.data,
            /* v */ ,
            /* r */,
            /* s */,
            provenCommitTx.isContractCreation
        ) = txProof(commitBlockHash, _proofBlob);

        require(
            provenCommitTxResultValid == TX_PROOF_RESULT_PRESENT
            
        );
        require(provenCommitTx.value >= unsignedUnlockTx.value);
        require(provenCommitTx.isContractCreation == false);
        require(provenCommitTx.data.length == 0);

        address submarine = ecrecover(
            unsignedUnlockTxHash,
            vee,
            keccak256(submarineId, byte(1)),
            keccak256(submarineId, byte(0))
        );

        require(provenCommitTx.to == submarine);
        sessions[submarineId].amountRevealed = uint96(unsignedUnlockTx.value);
        sessions[submarineId].commitTxBlockNumber = _commitTxBlockNumber;
        sessions[submarineId].commitTxIndex = uint16(provenCommitTxIndex);
        emit Revealed(
            submarineId,
            uint96(unsignedUnlockTx.value),
            _witness,
            commitBlockHash,
            submarine
        );

        onSubmarineReveal(
            submarineId,
            _embeddedDAppData,
            unsignedUnlockTx.value
        );
    }

    /**
     * @notice Function called by the submarine address to unlock the session.
     * @dev warning this function does NO validation whatsoever.
     *      ALL validation is done in the reveal.
     * @param _submarineId committed data; The commit instance representing the
     *        commit/reveal transaction
     */
    function unlock(bytes32 _submarineId) public payable {
        // Required to prevent an attack where someone would unlock after an
        // unlock had already happened, and try to overwrite the unlock amount.
        require(
            sessions[_submarineId].amountUnlocked < msg.value
           
        );
        sessions[_submarineId].amountUnlocked = uint96(msg.value);
        emit Unlocked(_submarineId, uint96(msg.value));
    }

    /**
     * @notice revealedAndUnlocked can be called to determine if a submarine
     *         send transaction has been successfully completed for a given
     *         submarineId
     * @param _submarineId committed data; The commit instance representing the
     *        commit/reveal transaction
     * @return bool whether the commit has a stored submarine send that has been
     *         completed for it (0 for failure / not yet finished, 1 for
     *         successful submarine TX)
     */
    function revealedAndUnlocked(
        bytes32 _submarineId
    ) public view returns(bool success) {
        SubmarineSession memory sesh = sessions[_submarineId];
        return sesh.amountUnlocked != 0
            && sesh.amountRevealed != 0
            && sesh.amountUnlocked >= sesh.amountRevealed;
    }
}



//import "../../openzeppelin-solidity/contracts/token/ERC721/IERC721.sol";

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

contract ERC721Auction is IERC721Receiver, LibSubmarineSimple {
  IERC721 public erc721;
  uint256 public erc721TokenId;

  address public seller;

  uint32 public startBlock;
  uint32 public endCommitBlock;
  uint32 public endRevealBlock;

  mapping (bytes32 => address) public bidders;
  bytes32 public winningSubmarineId;

  /// @notice This creates the auction.
  function onERC721Received(
    address _operator,
    address _from,
    uint256 _tokenId,
    bytes memory _data
  ) public returns(bytes4) {
    require(address(erc721) == 0x0);

    // In solidity 0.5.0, we can just do this:
    // (startBlock, endCommitBlock) = abi.decode(_data, (uint32, uint32));
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
    endCommitBlock = tempEndBlock;
    endRevealBlock = tempEndBlock + 256;

    require(block.number < startBlock);
    require(startBlock < endCommitBlock);
    require(endCommitBlock < endRevealBlock);
    erc721 = IERC721(msg.sender);
    erc721TokenId = _tokenId;
    seller = _from;

    return bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"));
  }

  function onSubmarineReveal(
    bytes32 _submarineId,
    bytes memory _embeddedDAppData,
    uint256 _value
  ) internal {
    require(address(erc721) != 0x0);
    require(startBlock <= block.number && block.number <= endRevealBlock);


    bidders[_submarineId] = msg.sender;
    if (getSubmarineAmount(winningSubmarineId) < _value) {
      winningSubmarineId = _submarineId;
    }
  }

  function finalize(bytes32 _submarineId) external {
    require(address(erc721) != 0x0);
    require(endRevealBlock < block.number);
    require(revealedAndUnlocked(_submarineId));
    require(bidders[_submarineId] == msg.sender);

    if (_submarineId == winningSubmarineId) {
      erc721.safeTransferFrom(address(this), msg.sender, erc721TokenId);
      seller.transfer(getSubmarineAmount(_submarineId));
    } else {
      msg.sender.transfer(getSubmarineAmount(_submarineId));
    }
  }
}
