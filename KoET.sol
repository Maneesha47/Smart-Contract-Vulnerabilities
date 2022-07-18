pragma solidity ^0.4.10;

contract KingOfTheEtherThrone {
   
    struct Monarch {
        // address of the king 
        address ethAddr ;
        string name ;
        // how much he pays to previous king
        uint claimPrice ;
        uint coronationTimestamp ;
    }
    Monarch public currentMonarch ;
    // claim the throne

    function claimThrone ( string name ) {

      

        if ( currentMonarch.ethAddr!= wizardAddress )

            currentMonarch.ethAddr.send (compensation);

        

        // assign the new king

        currentMonarch = Monarch (
            msg.sender , name , valuePaid , block.timestamp );
        }
}


