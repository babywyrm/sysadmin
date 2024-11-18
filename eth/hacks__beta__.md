# Ethereum Attacks

##
#
https://github.com/andreitoma8/learn-solidity-hacks
#
https://github.com/OpenZeppelin/ethernaut
#
https://github.com/ethereum/js-ethereum-cryptography
https://github.com/cleanunicorn/theo
https://github.com/ethpwn/ethpwn 
#
##


Security for internet applications is a spectrum, and it would be safe to assume that any application might have unnoticed vulnerabilities waiting to be exploited. Cryptocurrencies are especially attractive targets for hackers: because the technology is so novel, it is more likely to be hiding bugs, and the code usually interacts with tokens that have real-world value. Ethereum is no exception.

Attackers have successfully stolen ether using a number of tactics, which tend to aim at Ethereum smart contracts (written in Solidity), the network itself, cryptocurrency exchanges, or end users.

## Attacks on Smart Contracts

### The DAO

The DAO attack (Decentralized Autonomous Organization) is the largest and best known in Ethereum’s history, both because of its 3.6 million ether payout and its significant consequences for the ecosystem.

In June of 2016, a still-unknown attacker deployed a contract that would exploit a reentrancy bug in the DAO’s code to drain ether from the original contract into the attacker’s copy of it. The attacker was able to repeatedly invoke a function in the DAO that was intended to withdraw ether and then adjust the credit associated with the caller’s wallet accordingly. But in the case of the malicious contract, the `withdraw` function would repeat until the gas ran out, so the DAO could never reach the code that was meant to adjust the attacker’s credit and limit the withdraw. In effect, the attacker could have withdrawn as much ether as was available in the DAO contract. [1]

Because the attacker’s contract was a copy of the original DAO, it included a 28-day funding period. During this time, the ether sent to the contract would be untouchable, and this gave the Ethereum community time to formulate a response. There were three options seriously considered: do nothing, release a soft-fork that would block any attempts to withdraw the stolen ether from the malicious contract, or implement a hard-fork that would reset the history of the blockchain to just before the attack. [2] This encouraged passionate debate from the community, since any change to the underlying code was seen by critics as a betrayal of the ideals of blockchain technology: that trust could be offset by the irreversible law of code.

Ultimately, the Ethereum network implemented the hard-fork. Ethereum’s main chain branched off from a block that was mined before the attack occurred, so this new version of history could move forward as if nothing had happened. The chain that included the DAO attack maintained support from critics of the fork, however, and still remains somewhat active. This chain is now known as “Ethereum Classic” (ETC). [3]

### Parity Multisig Wallet

In July of 2017, an attacker exploited a vulnerability in Parity’s Multisig Wallet contract and stole more than 150,000 ether.

Parity is a software suite that implements an Ethereum client in Rust, along with an optional user interface for working with its built-in wallets and transaction functionality. One of those built-in wallets allows multiple owners to control its funds: this is more commonly referred to as a “multisig wallet.”

In an attempt to extract the constructor functionality out of the original multisig contract, Parity also inadvertently removed it from the scope of the contract’s permissions. A constructor function in Solidity is only executed once (when the contract is deployed), and in this case, it was responsible for establishing the addresses that could control the funds that would be held in the contract. [4]

Since the permissions in the main contract’s code no longer applied to the constructor once it was moved, anyone could then invoke it at any time after its deployment and set the owner of the wallet to an address of their choosing. In this way, the attacker was able to declare him or herself the sole owner of any Parity multisig wallet. Then it was simply a matter of sending its ether to the attacker’s own wallet.

Parity cited subtle difficulties in implementing permissions effectively in Solidity, and they released a patch for the bug shortly after the incident. [5] The Parity client and its standard single-owner wallets were unaffected by the attack.

### Malicious Contracts

In some cases, attacks can be represented by the initial contracts (rather than a malicious actor subverting the non-malicious intent of existing contracts, e.g. the DAO, Parity). Since these contracts gain public trust by exposing their code, they must find subtle ways to exploit users that will escape the notice of community audits.

Though these attacks are often less substantial or successful than other varieties, they have certainly been found in practice. One such example records a deposited amount of ether as a variable that would then, ostensibly, be available for withdrawal. The `withdraw` function, however, invokes a subtly different variable—in this case, it is differentiated by a single underscore—which is initialized as `0` and never changed. The user can never actually withdraw ether from the contract. [1][6]

### Unintentional Vulnerabilities

Contracts can also become “malicious” regardless of their developers’ intent. If a bug persists into the final, deployed contract and costs a user ether, it can be useful to think of it in the same context as the above-listed attacks—even if the project is not a verified scam. This is not meant to vilify the developers, but to ensure that the problems faced in the early years of Ethereum can be productively put to use in avoiding similar pitfalls for future contracts.

#### King of the Ether Throne

One such example, King of the Ether Throne, failed to account for the higher gas value that would be necessary for sending ether to a contract address (gas is the small amount of ether required to perform computations on the blockchain).

The flawed contract was a gambling scheme through which a user could buy the “crown” for a dynamic price. When a new “king” was crowned, the price for the crown would increase. Payments went mostly to the reigning king, with a small portion extracted for the contract owners.

If the reigning king used a contract address (rather than a simple wallet) to send his or her ether and assume the crown, the contract would attempt to send the payment from the incoming king back to the ousted king’s contract address. This should have been acceptable, since a contract can hold ether, but sending ether to a contract costs more gas than sending it to a wallet.

The problem here is two-fold: the contract failed to check for the success of the transaction before continuing its execution, and, of course, it also failed to allocate enough gas to send ether to a contract. [7] This meant that, in some cases, the payments would be silently reverted, but the contract would go on to crown the new king. This left the earnings from the previous king locked in the contract, accessible only by its owners. [8]

#### GovernMental

GovernMental hit a similar problem through slightly subtler means. The contract was a Ponzi scheme: users could send ether to it with the promise of an increased return, plus the chance to win a “jackpot.” The jackpot was collected from a portion of each participant’s entry, and was awarded to the last user to join in the event that no one else had sent ether to the contract in a twelve-hour period.

The contract stored its users’ addresses in a dynamically-sized array, and it needed to iterate over that array in order to clear it when a jackpot hit. It did not limit the size of the array, however, so GovernMental eventually attracted enough users that the gas allocation couldn’t cover the entire array. Since it would then always fail to reset the game and award the jackpot to the winner, the contract’s state was effectively frozen. [9]

#### Rock-Paper-Scissors

Though this contract was not as significant as others mentioned here, it is important to consider because of the vulnerability it exemplifies.

The contract implemented a simple game of “rock-paper-scissors,” in which a user could place a bet on the game and send one of the three options in what was supposed to be a secret message to the contract. In spite of Solidity’s `private` designation in the contract code, the transactions were—and always are—still visible on the blockchain. Cheating would simply be a matter of checking the most recent transaction associated with the contract’s address.

#### Further Reading

This is not meant to be a comprehensive list of possible vulnerabilities in Solidity design patterns. There are many more, some of which have already been exploited. Among them: a user could artificially drive the stack size up to a point where the targeted function will fail to execute, a contract could attempt to simulate randomness by insufficient means which could then be manipulated, or miners could adjust block timestamps to their benefit (e.g. to set themselves as the last recorded transaction in King of the Ether [8]).

Solidity developers should always stay up to date with security recommendations [10] and have their code audited to the greatest possible extent. 

## Attacks on the Network

The Ethereum network was (and remains) carefully designed to resist large-scale attacks. One of its primary tools for this is gas, which makes many types of attacks prohibitively expensive for the attacker. The protocol also dis-incentivizes miners breaking from the consensus reached by the majority of the chain, which prevents coalitions of rouge miners from re-writing history in some privately beneficial way. It is relevant to note here that a hard-fork, such as the one implemented after the DAO hack, could be accomplished for any reason, as long as the plot has the support of at least 51% of mining nodes.

Most of the complexity involved in the Ethereum platform’s development exists to discourage this kind of attack, and it has been exceptionally successful at resisting them. An upcoming change to the network’s consensus algorithm, Casper (an Ethereum-specific implementation of a “proof-of-stake” algorithm), aims to further improve the process. [16]

Despite the cost (in gas) needed to mount a traditional denial-of-service attack on the network, it fell victim to a string of them between late 2016 and early 2017. The attackers have been able to exploit bugs in blockchain clients to circumvent the cost, but notably, developers for these clients and for the Ethereum Foundation have been able to fix the problems quite rapidly. [17] The most recent attack was addressed within an hour. [18]

Denial-of-service attacks have had more of a substantial impact on Ethereum test networks (testnets), however. Testnets function like real blockchains, but their tokens do not hold real value. This enables developers to deploy contracts and interact with them in a realistic environment before they trust their code with real users’ money.

Since testnet ether is valueless, it is far more plausible to mount a denial-of-service attack against them. These can have real impacts on companies in the Ethereum space who depend on testnets to develop their product. In early 2017, an attack on the popular testnet Ropsten led to the emergence of entirely new test networks that would establish consensus in less vulnerable ways. [19] Rinkeby, for instance, uses the “proof-of-authority” model more popular in private blockchain implementations.

## Attacks on Exchanges

Cryptocurrency exchanges are services that allow a user to trade one currency for another. In some cases, this includes the exchange of fiat currency for crypto, but in most, it simply means one form of cryptocurrency for another.

There are many reasons for the notable proliferation of exchanges in recent years. For example, many exchanges are quite difficult to use, especially for new traders, plus exchanges can only support a finite number of tokens or coins. If a user wants one in particular, he or she may be forced to try a new exchange in order to acquire it.

The most notable feature for any exchange, however, is security. Exchanges deal with substantial transactions in huge volume, they are sparsely regulated, and many have limited resources for development and customer support. All these factors make them attractive targets for hackers.

The most well-known exchange attack in cryptocurrency as a whole was, without question, Mt. Gox—but since it predates Ethereum, it will not be discussed in detail here. 

#### Bithumb

In June of 2017, Bithumb—South Korea’s largest exchange and one of the five largest worldwide—lost billions of won and the sensitive data of around 30,000 users after an employee’s home computer was compromised. [11]

Despite Bithumb’s claim that no passwords had leaked, attackers were able to take over many accounts. [12] Of course, once an attacker has an email address and phone number, it is significantly easier for them to acquire the password for their victim’s account.

#### Bitfinex

In July of 2016, around $72 million in bitcoin was stolen from compromised Bitfinex accounts. Bitfinex, based in Hong Kong, is one of the world’s largest exchanges, and claimed to find no evidence of their servers having been infiltrated after an internal investigation. [13]

Bitfinex was also victim to two major denial-of-service attacks, one in mid-2015 and another in February of 2017. [14] Although a denial-of-service attack cannot directly steal cryptocurrency from its users, it interrupts the network so exchanges cannot be processed. When this occurs on an exchange with as much stature as Bitfinex, this can have an impact on the price of a given coin, and thus can be used to the attacker’s advantage.

#### Coinbase

Coinbase is another of the world’s largest exchanges. Its servers have never been compromised, but some of its users have been. And because Coinbase offers exchanges from fiat currency, it is exposed to fraudulent purchases and bank transfers. This fraud costs Coinbase about 10% of its revenue, which is about 20 times higher than PayPal’s loss rate from fraud. [15]

## Attacks on Users

Users are likely the most vulnerable vector for attack in the blockchain space, as they tend to be in the internet as a whole. Most of these attacks take familiar forms, but some are subtle enough to fool even blockchain experts. Users typically accept a higher risk than they might be used to—or aware of—when they buy, store, and trade cryptocurrency, especially if they lack a technical background. The exchange account takeovers mentioned in the previous section are examples of this.

### CoinDash

The CoinDash ICO (Initial Coin Offering) in July of 2017 is an attack that demonstrates how users can still be exposed to a higher risk than they encounter in the course of their daily internet use even if the hacker uses completely non-novel tactics. When a company releases their ICO, they reveal the address for an ICO contract that will receive ether and send some quantity of their own token in exchange. ICOs typically offer a better exchange rate than will be available once the token hits the market, so they have attracted substantial interest (and money) as they have become more common.

The attacker simply hacked the CoinDash site, where they were to publish the contract address when the ICO started, and displayed his or her own address there instead. Because ICOs are capped at a certain number of tokens, the event starts and ends in a matter of minutes—fast enough that the hacker received about $7.4 million before the fraudulent address could be replaced. [19]

### MyEtherWallet Clones

MyEtherWallet is a popular, open source interface for Ethereum wallets. It is well-audited and trusted throughout the community, and it is often recommended as the easiest interface for using hardware wallets. Since all its code is published openly, however, it is exceptionally easy to create a fake version of the website and collect the keys that users freely give them.

This is certainly the least novel attack—and MyEtherWallet is just one example of many—but that does not make it any less of a risk for novice users. In fact, Google Ads promotes one of these phishing sites in its results for “MyEtherWallet” above the real thing. It is never safe to trust private keys with a third party before researching that party quite extensively, and that level of responsibility is not always obvious for new users.

## References 

Please note: Reddit threads are not inherently trustworthy sources. The discussions referenced here are significant only because they include important commentary by verified and substantial members of the Ethereum community, or because they contain information that is vital but otherwise unavailable.

[1] https://blog.ethereum.org/2016/06/19/thinking-smart-contract-security/    
[2] https://www.coindesk.com/understanding-dao-hack-journalists/     
[3] https://blockgeeks.com/guides/what-is-ethereum-classic/     
[4] https://blog.zeppelin.solutions/on-the-parity-wallet-multisig-hack-405a8c12e8f7     
[5] https://blog.ethcore.io/the-multi-sig-hack-a-postmortem/     
[6] https://www.reddit.com/r/ethereum/comments/4e5y30/live_example_of_underhanded_solidity_coding_on/?st=j8t4fp8g&sh=a21522eb     
[7] http://www.kingoftheether.com/postmortem.html     
[8] https://eprint.iacr.org/2016/1007.pdf     
[9] https://www.reddit.com/r/ethereum/comments/4ghzhv/governmentals_1100_eth_jackpot_payout_is_stuck/?st=j8t68ln9&sh=c2d90383     
[10] https://github.com/ConsenSys/smart-contract-best-practices     
[11] https://motherboard.vice.com/en_us/article/bjxnjw/south-koreas-largest-ethereum-exchange-was-hacked     
[12] https://bravenewcoin.com/news/fourth-largest-bitcoin-exchange-bithumb-hacked-for-billions-of-won/     
[13] https://www.reuters.com/article/us-bitfinex-hacked-hongkong/bitcoin-worth-72-million-stolen-from-bitfinex-exchange-in-hong-kong-idUSKCN10E0KP     
[14] https://www.cryptocoinsnews.com/bitfinex-targeted-in-severe-ddos-attack-amid-bitcoin-price-surge/     
[15] https://www.cryptocoinsnews.com/bitfinex-targeted-in-severe-ddos-attack-amid-bitcoin-price-surge/     
[16] https://github.com/ethereum/wiki/wiki/Proof-of-Stake-FAQ     
[17] https://www.coindesk.com/so-ethereums-blockchain-is-still-under-attack/     
[18] https://www.coindesk.com/ethereum-developers-stymie-blockchain-spammers-latest-attack/     
[19] https://motherboard.vice.com/en_us/article/zmvg58/hacker-allegedly-steals-dollar74-million-in-ethereum-with-incredibly-simple-trick     
