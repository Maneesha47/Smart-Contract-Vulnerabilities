pragma solidity ^0.4.10;

contract theRun {
   uint private Last_Payout = 0;
   uint256 salt = block.timestamp ;
   
   function random() returns(uint256 result) {
      uint256 y = salt * block.number /( salt %5);
      uint256 seed = block.number /3 + ( salt %300) + Last_Payout +y ;
      
      // h = the blockhash of the seed - th last block
      uint256 h = uint256 ( block.blockhash(seed));
      
      // random number between 1 and 100
      return uint256 ( h % 100) + 1;
   }
}



