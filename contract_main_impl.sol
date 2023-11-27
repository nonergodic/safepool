pragma solidity ^0.4.23;

interface ERC20
{
    function balanceOf(address tokenDeployer) external constant returns (uint balance);
    //0xa9059cbb = transfer signature = keccak256(transfer(address,uint256))
    //0x095ea7b3 = approve signature = keccak256(approve(address,uint256))
}

contract SafePoolImpl
{
    // ============================================= CONSTANTS =============================================
    uint private constant ContractVersion = 2;

    uint private constant CommandSize    =  1;
    uint private constant FlagsSize      =  1;
    uint private constant IndexSize      =  1;
    uint private constant TokenDropsSize =  1;
    uint private constant BoolSize       =  1;
    uint private constant TimeSize       =  4;
    uint private constant GasSize        =  4;
    uint private constant EthAmountSize  = 16;
    uint private constant AddressSize    = 20;
    uint private constant SlotSize       = 32;
    uint private constant SigFlagsSize   = 1; //for now, SigFlags are only used for whitelisting members
    uint private constant SigVSize       = 1;
    uint private constant SigRSize       = 32;
    uint private constant SigSSize       = 32;
    uint private constant TotalSigSize   = SigFlagsSize + SigVSize + SigRSize + SigSSize;

    /*[[[cog
    import cog, deploy_utils

    addrs = deploy_utils.readConfigAddrs(chainId)

    cog.outl('address private constant AddrSafePoolAutoDist    = address('+addrs['AUTODIST']+');')
    cog.outl('address private constant AddrSafePoolMaintenance = address('+addrs['MAINTENANCE']+');')
    cog.outl('address private constant AddrSafePoolFee         = address('+addrs['FEE']+');')
    ]]]*/

    address private constant AddrSafePoolAutoDist    = address(0xd157D157D157d157d157d157D157d157d157d157);
    address private constant AddrSafePoolMaintenance = address(0x0FF1CE0ff1cE0FF1Ce0FF1ce0Ff1CE0ff1Ce0fF1);
    address private constant AddrSafePoolFee         = address(0xfeEFEEfeefEeFeefEEFEEfEeFeefEEFeeFEEFEeF);

    //[[[end]]]

    uint private constant SafePoolFeeRatio = 0.0045 ether;
    uint private constant TokenDropEthFeePerMember = 0.006 ether;
    uint private constant DefaultGasAllowance = 100000;
    uint private constant LoopGasRequirement = 90000;
    uint private constant TokenBalanceSanityThreshold = uint(1) << (16*8);
    uint private constant PoolLockTimeout = 4 weeks;

    uint private constant ComplementaryRatio = (1 ether - SafePoolFeeRatio);

    // ======================= COMMAND MASKS =====================================

    // single commands (some only available to admin, but most also to users) ...
    // ... calldata that contains a single command must not contain any other command
    uint private constant SingleCmdMask = 0x80; //most significant bit

    // admin commands that expect an address as their first parameter (and perhaps other values after)
    uint private constant AddressCmdMask = 0x40; //second most significant bit

    // member commands share similar code and hence got their own subgroup
    uint private constant MemberSubMask  = 0x20; //third most significant bit

    // admin commands with various (or no) parameters
    uint private constant VariousCmdMask = 0x10; //fourth most significant bit

    // listing signatures of other public/external functions:
    //   ensures that there can't be a clash by having such a function that starts with the
    //   same byte as one of the shortened commands that are used in the fallback function
    // 0xc0ee0b8a = tokenFallback signature = keccak256(tokenFallback(address,uint256,bytes))
    // 0xfee4c708 = abiVersion signature = keccak256(abiVersion())
    // 0xe7a26a6a = viewList signature = keccak256(viewList(uint256,uint256,uint256))

    // ======================= COMMANDS ==========================================

    // ---------- 1 byte Command Signatures for Fallback Function -----------------
    // 4 most significant bits are command type signifier
    // 4 least significant bits specify the actual command
    uint private constant CmdDeposit             = 0x0 + SingleCmdMask;
    uint private constant CmdWithdraw            = 0x1 + SingleCmdMask;
    uint private constant CmdClaimTokens         = 0x2 + SingleCmdMask;
    uint private constant CmdAutoDistTokens      = 0x3 + SingleCmdMask;
    uint private constant CmdAutoDistRefunds     = 0x4 + SingleCmdMask;
    uint private constant CmdRefund              = 0x5 + SingleCmdMask;
    uint private constant CmdSubmit              = 0x6 + SingleCmdMask;
    uint private constant CmdForward             = 0x7 + SingleCmdMask;
    uint private constant CmdClaimAdminFees      = 0x8 + SingleCmdMask;
    uint private constant CmdClaimSafePoolFees   = 0x9 + SingleCmdMask;
    uint private constant CmdEmergencyRegRefund  = 0xA + SingleCmdMask;
    uint private constant CmdSafePoolRecord      = 0xB + SingleCmdMask;
    //uint private constant CmdRequestAutoDist     = 0xC + SingleCmdMask;
    uint private constant CmdBestowTokenDrops    = 0xD + SingleCmdMask;
    uint private constant CmdSafePoolCancel      = 0xE + SingleCmdMask;

    // Member commands
    uint private constant CmdMemberSetFlags      = 0x0 + AddressCmdMask + MemberSubMask;
    uint private constant CmdMemberSetMinMax     = 0x1 + AddressCmdMask + MemberSubMask;
    uint private constant CmdMemberReduceTo      = 0x2 + AddressCmdMask + MemberSubMask;
    uint private constant CmdMemberExclude       = 0x3 + AddressCmdMask + MemberSubMask;
    uint private constant CmdMemberReinclude     = 0x4 + AddressCmdMask + MemberSubMask;

    // Admin address commands
    uint private constant CmdAdvStageConfig      = 0x0 + AddressCmdMask;
    uint private constant CmdRegAdmin            = 0x1 + AddressCmdMask;
    uint private constant CmdRegTokenContract    = 0x2 + AddressCmdMask;
    uint private constant CmdRegRefundSource     = 0x3 + AddressCmdMask;
    uint private constant CmdSetFundsRecipient   = 0x4 + AddressCmdMask;
    uint private constant CmdSetFeeRecipient     = 0x5 + AddressCmdMask;
    uint private constant CmdUnregTokenContract  = 0x6 + AddressCmdMask;
    uint private constant CmdUnregRefundSource   = 0x7 + AddressCmdMask;
    uint private constant CmdUnregAdmin          = 0x8 + AddressCmdMask;
    uint private constant CmdLockFundsRecipient  = 0x9 + AddressCmdMask;
    uint private constant CmdLockFeeRecipient    = 0xA + AddressCmdMask;
    uint private constant CmdSetDeployer         = 0xB + AddressCmdMask;
    uint private constant CmdSetAuthKey          = 0xC + AddressCmdMask;
    uint private constant CmdRequestAutoDist     = 0xD + AddressCmdMask;

    // Other admin commands
    uint private constant CmdSetDefaultMinMax    = 0x0 + VariousCmdMask;
    uint private constant CmdSetTimeContrib      = 0x1 + VariousCmdMask;
    uint private constant CmdSetTimeSwitchOff    = 0x2 + VariousCmdMask;
    uint private constant CmdSetTimeouts         = 0x3 + VariousCmdMask;
    uint private constant CmdSetPoolMax          = 0x4 + VariousCmdMask;
    uint private constant CmdSetPoolFees         = 0x5 + VariousCmdMask;
    uint private constant CmdSetGasAllowance     = 0x6 + VariousCmdMask;
    uint private constant CmdAdvStagePooling     = 0x7 + VariousCmdMask;
    uint private constant CmdCancel              = 0x8 + VariousCmdMask;
    uint private constant CmdSetStorage          = 0x9 + VariousCmdMask;
    uint private constant CmdCheckStorage        = 0xA + VariousCmdMask;
    uint private constant CmdSetMetadata         = 0xB + VariousCmdMask;
    uint private constant CmdRecord              = 0xC + VariousCmdMask;
    uint private constant CmdSetTokenDrops       = 0xD + VariousCmdMask;
    // TODO:
    // uint private constant CmdSetSubmitCalldata   = 0xE + VariousCmdMask; //can't be normal multi-command because of variable length
    // uint private constant CmdLockSubmitCalldata  = 0xF + VariousCmdMask;

    //                    NullIsReserved         = 0x0;
    uint private constant CmdPoolLockOn          = 0x1;
    uint private constant CmdPoolLockOff         = 0x2;
    uint private constant CmdWhitelistOn         = 0x3;
    uint private constant CmdWhitelistOff        = 0x4;
    uint private constant CmdDepositOnBehalfOn   = 0x5;
    uint private constant CmdDepositOnBehalfOff  = 0x6;
    uint private constant CmdAdminPanicOn        = 0x7;
    uint private constant CmdAdminPanicOff       = 0x8;
    uint private constant CmdAdminListLockOn     = 0x9;
    uint private constant CmdAdminListLockOff    = 0xA;
    uint private constant CmdTokenApproveLockOn  = 0xB;
    uint private constant CmdTokenApproveLockOff = 0xC;
    uint private constant CmdDisableWithdrawOn   = 0xD;
    uint private constant CmdDisableWithdrawOff  = 0xE;
    uint private constant CmdVerificationOn      = 0xF;
    // --------------------------------------------------------------------

    // ---------- Offsets for Contract status[] --------------------------

    // status
    uint private constant StatWhitelist            = uint(1) << 0;
    uint private constant StatDepositOnBehalf      = uint(1) << 1;
    uint private constant StatDisableWithdraw      = uint(1) << 2;
    uint private constant StatVerification         = uint(1) << 3;

    // meta-status
    uint private constant StatFundsRecipientLocked = uint(1) << 0 + (1*8);
    uint private constant StatTokenApprovalLocked  = uint(1) << 1 + (1*8);
    uint private constant StatFeeRecipientLocked   = uint(1) << 2 + (1*8);
    uint private constant StatAdminListLocked      = uint(1) << 3 + (1*8);

    // special states
    uint private constant StatCancelled            = uint(1) << 0 + (2*8);
    uint private constant StatPoolingLocked        = uint(1) << 1 + (2*8);
    uint private constant StatAdminPanic           = uint(1) << 2 + (2*8);
    uint private constant StatAdminFeeUnlocked     = uint(1) << 3 + (2*8);

    // stages - have to occupy most significant bits for < and >= operators
    uint private constant StatConfiguring          = uint(1) << 0 + (3*8);
    uint private constant StatPooling              = uint(1) << 1 + (3*8);
    uint private constant StatSubmitted            = uint(1) << 2 + (3*8);
    // --------------------------------------------------------------------

    // offsets for flagsNext uints:
    //   the upper 12 byte represent flags (almost entirely unused)
    //   the lower 20 byte represent the address of the next element in the mapping
    uint private constant FlagsOffset      = AddressSize * 8;
    //  ----------  Generic flags -----------------------------------------
    uint private constant FlagExists       = uint(1) <<  0 + FlagsOffset; // used for marking record as existing
    uint private constant FlagApproved     = uint(1) <<  1 + FlagsOffset; // approval means whitelisted for members
    //  ----------  Member flags ------------------------------------------
    uint private constant FlagExcluded     = uint(1) <<  2 + FlagsOffset; // member is excluded from the pool
    uint private constant FlagUnlocked     = uint(1) <<  3 + FlagsOffset; // member unlocked for depositing
    uint private constant FlagCustomLimits = uint(1) <<  4 + FlagsOffset; // enforce member limits
    uint private constant FlagSkipAutoDist = uint(1) <<  5 + FlagsOffset; // member skipped in auto distribution
    uint private constant FlagVerified     = uint(1) <<  7 + FlagsOffset; // member has deposited with valid signature
    //  ----------  Token flags -------------------------------------------
    uint private constant FlagPublicExists = uint(1) <<  6 + FlagsOffset;
    // --------------------------------------------------------------------
    // bitmask used to reset all flags that can be changed by the CmdMemberSetFlags command for an existing member
    uint private constant ResetMemberFlags = (FlagExists|FlagExcluded|FlagVerified) | uint(2**(FlagsOffset)-1);

    // ======================================= EVENTS and STRUCTS =======================================

    event HistoryEntry(uint entry);
    event Record(uint record);
    event SafePoolRecord(uint sprecord);
    event AutoDistRequest(address tc);
    event MemberReduceToFailedFor(address member);
    event AutoDistTokenFailedFor(address member, address tc);
    event AutoDistRefundFailedFor(address member);

    struct Member
    {
        uint flagsNext;
        uint128 contribution;
        uint128 refundReceived;
        uint128 minContrib;
        uint128 maxContrib;
    }

    struct TokenContract
    {
        uint flagsNext;
        uint tokensWithdrawn;
        uint claimedAdminFee;
        uint claimedSafePoolFee;
        address addrAutoDistNext;
        address publicNext;
    }

    // ============================================== DATA ==============================================

    // FIXED SLOTS ============
    // Do not change the order of these variables and do not declare anything above this comment
    // If you need more fixed members, add to the end of the list

    /*  0 */ address private addrDeployer;
    /*  1 */ address private addrMembersHead; // needs to initialise, so that the first member is not penalised unfairly
                                              // (still 10k gas more than subsequent members though)

    // FIXED SLOTS END =========
    address private addrAdminsHead;
    address private addrRefundSourcesHead;
    address private addrAdminTokenContractsHead;
    address private addrPublicTokenContractsHead;
    address private addrRefundAutoDistNext;

    address private addrFundsRecipient;
    address private addrFeeRecipient;

    uint private timeContribStart;
    uint private timeContribEnd;
    uint private timeSwitchOffMaxContrib;
    uint private timeSwitchOffWhitelist;
    uint private timeSubmitTimeout;
    uint private timeEthFeeTimeout;

    uint private timePoolLockedOn;
    uint private totalLockedDuration;

    uint private gasAllowance;
    uint private memberDefaultMin;
    uint private memberDefaultMax;
    uint private poolMaximum;
    uint private adminEthFeeRatio;
    uint private adminTokenFeeRatio;

    uint private poolBalance;
    uint private refundWithdrawn;
    uint private excludedMemberBalance;
    uint private unclaimedAdminEthFee;
    uint private unclaimedSafePoolEthFee;
    uint private status;

    mapping(address => Member) private members;
    mapping(address => uint) private admins;
    mapping(address => uint) private refundSources;
    mapping(address => TokenContract) private tokenContracts;
    mapping(address => mapping(address => uint)) private memberTokensReceived; // mtr[memberAddr][erc20addr]

    bool private reentrancyLock;
    uint8 private tokenDropsLeft;
    uint8 private tokenDropsCompleted;
    uint private memberCount;
    address private addrAuthKey;

    uint[256] private metadata;

    // ============================================= FUNCTIONS =============================================

    // return list in one go, to be used with eth_call, has no effect on the contract
    // signature does not clash with commands - see documentation block before commands
    function viewList(uint listType,uint start,uint maxCount) external view
    { //[assembly code to read the state of the contract with a single eth node request - removed for readability]
    }

    // signature does not clash with commands - see documentation block before commands
    function tokenFallback(address from, uint256 value, bytes data) external
    {
        require(  (status & StatSubmitted) != 0    //only accepted tokens in submitted stage ...
               && value > 0                        //... and no calls that only have data ...
               && (  members[from].flagsNext == 0  //... and not from members ...
                  || (  data.length == CommandSize
                     && uint(data[0]) == CmdRefund //... unless they explicitly want to refund and nothing else
                     )
                  )
               );

        TokenContract storage tc = tokenContracts[msg.sender];
        if (tc.flagsNext == 0)
        {
            require(msg.sender > 1 && (status & StatAdminPanic) == 0);
            tc.flagsNext = FlagPublicExists;
            tc.publicNext = addrPublicTokenContractsHead;
            addrPublicTokenContractsHead = msg.sender;

            //by emitting a HistoryEntry event here we guarantee that ...
            //... any change to the storage of the contract is associated with a HistoryEntry event
            emit HistoryEntry((poolBalance<<64) + now); //cmd is left 0 for tokenFallback
        }
    }

    function tokenTransfer(uint gasLimit, address tc, address recipient, uint amount) private returns(bool success) {
        assembly {
            let cdPtr := mload(0x40)
            //0xA9059CBB = keccak256(transfer(address,uint256))
            mstore(cdPtr, 0xA9059CBB00000000000000000000000000000000000000000000000000000000)
            mstore(add(cdPtr,4), recipient)
            mstore(add(cdPtr,36/*4+32*/), amount)
            let retPtr := add(cdPtr,68/*4+32+32*/)
            mstore(retPtr, 0x1)
            switch gasLimit
                case 0  { success := call(gas     , tc, 0, cdPtr, 68/*4+32+32*/, retPtr, 32) }
                default { success := call(gasLimit, tc, 0, cdPtr, 68/*4+32+32*/, retPtr, 32) }
            //we either got a return value which is stored in retPtr, or it will contain 0x1 that we stored before
            success := and(success, mload(retPtr))
        }
    }

    function fromCallData(uint idx, uint size) private pure returns(uint ret)
    {
        assembly {
            let l := calldataload(idx)
            let d := exp(256,sub(32,size))
            ret := div(l,d)
        }
    }

    function isAdmin() private view returns(bool)
    {
        uint tmpStatus = status;
        return ( ( tmpStatus >= StatConfiguring
                 ? (admins[msg.sender] & FlagApproved) != 0
                 : msg.sender == addrDeployer
                 )
               || (tmpStatus & StatAdminPanic) != 0 //fallback function ensures that msg.sender == AddrSafePoolMaintenance
               );
    }

    function isCancelled() private view returns(bool)
    {
        uint tmpStatus = status;
        return (   (tmpStatus & StatCancelled ) != 0
               || ((tmpStatus & StatPooling  ) != 0 && now > (timeSubmitTimeout-1))
               || (  (tmpStatus & StatSubmitted) != 0
                  && (tmpStatus & StatAdminFeeUnlocked) == 0
                  && now > (timeEthFeeTimeout-1)
                  )
               );
    }

    function ensureTokenContractExistsAndReturnBalance(address addr) private returns(uint)
    {
        //assert(addr != address(this)); //checked on all code paths leading here
        //EXTERNAL_CALL -- safe, ERC20 contracts are isolated
        uint tokenBalance = ERC20(addr).balanceOf(address(this));
        require(tokenBalance > 0 && tokenBalance < TokenBalanceSanityThreshold);
        TokenContract storage tc = tokenContracts[addr];
        if (tc.flagsNext == 0)
        {
            require(addr > 1);
            tc.flagsNext = FlagPublicExists;
            tc.publicNext = addrPublicTokenContractsHead;
            addrPublicTokenContractsHead = addr;
        }
        return tokenBalance;
    }

    function deposit() private
    {
        require(msg.value > 0);
        address addr;
        uint tmpFlagsNext;
        if (msg.data.length == 0 || msg.data.length == CommandSize || msg.data.length == CommandSize + TotalSigSize)
        {
            addr = msg.sender;
            Member storage m = members[addr];
            tmpFlagsNext = m.flagsNext;
            //only accept command-less contributions from known members ...
            //...  (to e.g. prevent accepting contributions from exchanges)
            require(msg.data.length != 0 || tmpFlagsNext != 0 || isAdmin());
        }
        else if (  msg.data.length == CommandSize + AddressSize
                || msg.data.length == CommandSize + TotalSigSize + AddressSize
                )
        {
            addr = address(fromCallData( ( msg.data.length == CommandSize + AddressSize
                                         ? CommandSize
                                         : CommandSize + TotalSigSize
                                         )
                                       , AddressSize
                                       )
                          );
            require(((status & StatDepositOnBehalf) != 0 || isAdmin()) && addr > 1 && addr != address(this));
            m = members[addr];
            tmpFlagsNext = m.flagsNext;
        }
        else
            revert();
        
        if ((tmpFlagsNext & FlagVerified) == 0 && msg.data.length >= CommandSize + TotalSigSize)
        {
            bool approve = (fromCallData(CommandSize, SigFlagsSize) > 0);
            require(ecrecover( keccak256(abi.encodePacked( "\x19Ethereum Signed Message:\n32"
                                                         , bytes11(0)
                                                         , bytes1(approve ? 1 : 0)
                                                         , addr
                                                         ))
                             ,   uint8(fromCallData(CommandSize + SigFlagsSize                      , SigVSize))
                             , bytes32(fromCallData(CommandSize + SigFlagsSize + SigVSize           , SigRSize))
                             , bytes32(fromCallData(CommandSize + SigFlagsSize + SigVSize + SigRSize, SigSSize))
                             ) == addrAuthKey
                   );
            
            tmpFlagsNext |= FlagVerified;
            if ((tmpFlagsNext & FlagExists) != 0)
                m.flagsNext = tmpFlagsNext;
            else if (approve)
                tmpFlagsNext |= FlagApproved;
        }
        
        uint tmpStatus = status;
        require(  (tmpStatus & StatPooling) != 0                    //depositing is only possible during pooling stage ...
               && !isCancelled()                                    //... and pool must not be cancelled ...
               && (tmpFlagsNext & FlagExcluded) == 0                //... and member must not be excluded ...
               && (  (  (  (tmpStatus & StatVerification) == 0      //... and pool does not require verification ...
                        || (tmpFlagsNext & FlagVerified) != 0       //... or member has been verified ...
                        )
                     && (  (tmpFlagsNext & FlagUnlocked) != 0       //... and the member is either unlocked ...
                        || (  (tmpStatus & StatPoolingLocked) == 0  //... or the pool has not been locked ...
                           && now >= timeContribStart               //... and we are within the contribution time frame ...
                           && now <= (timeContribEnd-1)
                           && (  (tmpStatus & StatWhitelist) == 0   //... and whitelist is either off ...
                              || (tmpFlagsNext & FlagApproved) != 0 //... or member is whitelisted ...
                              || now > (timeSwitchOffWhitelist-1)   //... or whitelisting has been auto-switched off ...
                              )
                           )
                        )
                     )
                  || isAdmin()                                      //... or it's an admin who is issuing the deposit
                  )
               );

        uint tmpContribution = m.contribution;
        if (tmpContribution == 0)
            memberCount += 1;

        tmpContribution += msg.value;
        poolBalance += msg.value;

        if (!isAdmin()) //admins ignore limits
        {
            if ((tmpFlagsNext & FlagCustomLimits) != 0)
            {
                uint cmin = m.minContrib;
                uint cmax = m.maxContrib;
            }
            else
            {
                cmin = memberDefaultMin;
                cmax = memberDefaultMax;
            }

            require(  tmpContribution >= cmin
                   && (  (tmpContribution-1) <= (cmax-1) //lhs -1 <= rhs -1 used to handle cmax = 0
                      || now > (timeSwitchOffMaxContrib-1)
                      )
                   && (poolBalance-1) <= (poolMaximum-1) //lhs -1 <= rhs -1 used to handle poolMaximum = 0
                   );
        }

        if ((tmpFlagsNext & FlagExists) == 0)
        {
            tmpFlagsNext |= FlagExists | uint(addrMembersHead);
            m.flagsNext = tmpFlagsNext;
            addrMembersHead = addr;
        }

        m.contribution = uint128(tmpContribution);
    }

    function withdraw() private
    {
        Member storage m = members[msg.sender];
        uint tmpContribution = m.contribution;
        require(msg.value == 0 && tmpContribution > 0 && !reentrancyLock);
        uint tmpFlagsNext = m.flagsNext;
        uint tmpStatus = status;

        if ((tmpStatus & StatPooling) != 0 && !isCancelled())
        {   //withdraw
            require(  (tmpFlagsNext & (FlagUnlocked|FlagExcluded)) != 0
                   || (  (tmpStatus & StatDisableWithdraw) == 0
                      && (  (tmpStatus & StatPoolingLocked) == 0
                         || (totalLockedDuration + (now - timePoolLockedOn) > PoolLockTimeout)
                         )
                      )
                   || isAdmin()
                   );

            uint amount; //is zero initialized (= 0 increases gas cost unecessarily)
            if (msg.data.length > CommandSize)
            {
                require(msg.data.length == CommandSize + EthAmountSize);
                amount = fromCallData(CommandSize, EthAmountSize);
            }

            require(amount <= tmpContribution);
            amount = (amount == 0) ? tmpContribution : amount;

            tmpContribution -= amount;
            m.contribution = uint128(tmpContribution);

            if ((tmpFlagsNext & FlagExcluded) == 0)
            {
                require(  tmpContribution == 0
                       || tmpContribution >= (((tmpFlagsNext & FlagCustomLimits) == 0) ? memberDefaultMin : m.minContrib)
                       );
                poolBalance -= amount;

                if (tmpContribution == 0)
                    memberCount -= 1;
            }
            else
                excludedMemberBalance -= amount;
        }
        else
        {   //refund
            require((isCancelled() || (tmpStatus & StatSubmitted) != 0) && msg.data.length <= CommandSize);
            if ((tmpFlagsNext & FlagExcluded) != 0)
            {
                amount = tmpContribution;
                excludedMemberBalance -= amount;
                m.contribution = 0;
            }
            else
            {
                uint tmpRefundWithdrawn = refundWithdrawn;
                uint tmpUnclaimedAdminEthFee = unclaimedAdminEthFee;
                if (  tmpUnclaimedAdminEthFee > 0
                   && now > (timeEthFeeTimeout-1)
                   && (tmpStatus & StatAdminFeeUnlocked) == 0
                   )
                {
                    tmpUnclaimedAdminEthFee = 0;
                }
                amount = ( address(this).balance
                         + tmpRefundWithdrawn
                         - excludedMemberBalance
                         - unclaimedSafePoolEthFee
                         - tmpUnclaimedAdminEthFee
                         )
                       * tmpContribution
                       / poolBalance;

                //assert(amount >= tmpRefundReceived);
                uint tmpRefundReceived = m.refundReceived;
                m.refundReceived = uint128(amount);
                amount -= tmpRefundReceived;
                refundWithdrawn = tmpRefundWithdrawn + amount;
            }
        }
        //EXTERNAL_CALL -- safe, strictly follows checks-effects-interactions pattern
        require(msg.sender.call.value(amount)());
    }

    function parseTransactionPayload() private view returns (address addr, uint amount, bytes memory data)
    {
        uint dataidx = CommandSize;
        addr = address(fromCallData(dataidx, AddressSize));
        dataidx += AddressSize;
        amount = fromCallData(dataidx, EthAmountSize);
        dataidx += EthAmountSize;
        require(dataidx <= msg.data.length && addr != address(this) && addr > 1);

        if (dataidx < msg.data.length)
        {
            uint forwardedDataLength = msg.data.length - dataidx;
            data = new bytes(forwardedDataLength);
            assembly {calldatacopy(add(data,32), dataidx, forwardedDataLength)} //add 32 to skip size of data
        }
    }

    function submit() private
    {
        require(isAdmin() && (status & StatPooling) != 0 && !isCancelled() && msg.value == 0);

        address addr;
        uint lowerBound;
        bytes memory data;
        (addr, lowerBound, data) = parseTransactionPayload();
        
        if (addr != addrFundsRecipient) {
            require((status & StatFundsRecipientLocked) == 0);
            addrFundsRecipient = addr;
        }

        uint submitBalance = poolBalance;
        if (submitBalance-1 > poolMaximum-1)
            submitBalance = poolMaximum;

        unclaimedAdminEthFee = submitBalance * adminEthFeeRatio / (1 ether);
        unclaimedSafePoolEthFee = submitBalance * SafePoolFeeRatio / (1 ether)
                                + memberCount * tokenDropsLeft * TokenDropEthFeePerMember;

        uint totalFees = unclaimedAdminEthFee + unclaimedSafePoolEthFee;
        require(totalFees < submitBalance); //implicitly checks for submitBalance > 0

        uint submitValue = submitBalance - totalFees;
        require(  submitValue >= lowerBound
               //prevent deposit on behalf
               && (  (  data.length != (CommandSize+AddressSize)
                     && data.length != (CommandSize+TotalSigSize+AddressSize)
                     )
                  || uint(data[0]) != CmdDeposit
                  )
               );

        status += StatPooling; //advance to submitted stage

        //EXTERNAL_CALL -- safe, follows checks-effects-interactions pattern
        assembly { if iszero(call(gas, addr, submitValue, add(data,32), mload(data), 0, 0)) {revert(0,0)} }
    }

    function forward() private
    {
        require(isAdmin());

        address addr;
        uint amount;
        bytes memory data;
        (addr, amount, data) = parseTransactionPayload();

        if (msg.sender != AddrSafePoolMaintenance)
        {
            require(  amount == msg.value
                   && (  data.length <= CommandSize //CommandSize bytes of data (at most) can always be forwarded
                      || (  status < StatSubmitted  //longer data forwards are only available before submission ...
                         && (  data.length < 4      //... or by involving SafePool using AdminPanic
                            || data[0] != 0x09      //prevent admin from using ERC20 approve function:
                            || data[1] != 0x5e      //using approve in the pooling stage, the admin could set up ...
                            || data[2] != 0xa7      //... an allowance for himself, to steal tokens later
                            || data[3] != 0xb3      //0x095ea7b3 = keccak256(approve(address,uint256))
                            )
                         )
                      )
                   );
        }

        assembly { if iszero(call(gas, addr, amount, add(data,32), mload(data), 0, 0)) {revert(0,0)} }
    }

    function transferTokensToSender(address tc, uint contribution, uint tokenBalance) private
    {
        uint tmpTokensWithdrawn = tokenContracts[tc].tokensWithdrawn;
        uint totalTokenBalance = tokenBalance + tmpTokensWithdrawn;
        uint tmpAdminTokenFee = adminTokenFeeRatio;
        if (tmpAdminTokenFee > 0)
        {
            totalTokenBalance *= (ComplementaryRatio - tmpAdminTokenFee);
            totalTokenBalance /= (1 ether);
        }

        uint totalTokenShare = totalTokenBalance * contribution / poolBalance;

        uint tmpMemberTokensReceived = memberTokensReceived[msg.sender][tc];

        if (totalTokenShare > tmpMemberTokensReceived)
        {
            uint unclaimedTokenShare = totalTokenShare - tmpMemberTokensReceived;
            memberTokensReceived[msg.sender][tc] = totalTokenShare;
            tokenContracts[tc].tokensWithdrawn = tmpTokensWithdrawn + unclaimedTokenShare;

            if (  (status & StatAdminFeeUnlocked) == 0
               && (tokenContracts[tc].flagsNext & FlagApproved) != 0
               && now <= (timeEthFeeTimeout-1)
               )
            {
                status |= StatAdminFeeUnlocked;
            }

            //EXTERNAL_CALL -- safe, follows checks-effects-interactions pattern, ...
            //                 ... protected by reentrancyLock, and ERC20 contracts are isolated
            require(tokenTransfer(0, tc, msg.sender, unclaimedTokenShare));
        }
        //else assert(totalTokenShare == tmpMemberTokensReceived);
    }

    function claimTokens() private
    {
        require(msg.value == 0 && (status & StatSubmitted) != 0 && !reentrancyLock);

        Member storage m = members[msg.sender];
        require(m.contribution > 0 && (m.flagsNext & FlagExcluded) == 0);

        if (msg.data.length > CommandSize) //claim tokens for a single contract
        {
            address tc = address(fromCallData(CommandSize, AddressSize));
            require((msg.data.length == CommandSize + AddressSize) && tc != address(this));

            uint tokenBalance = ensureTokenContractExistsAndReturnBalance(tc);
            transferTokensToSender(tc, m.contribution, tokenBalance);
        }
        else //convenience loop through all approved contracts
        {
            for(tc = addrAdminTokenContractsHead; tc > 1; tc = address(tokenContracts[tc].flagsNext))
            {
                if ((tokenContracts[tc].flagsNext & FlagApproved) != 0)
                {
                    //EXTERNAL_CALL -- safe, ERC20 contracts are isolated
                    tokenBalance = ERC20(tc).balanceOf(address(this));
                    require(tokenBalance < TokenBalanceSanityThreshold);
                    transferTokensToSender(tc, m.contribution, tokenBalance);
                }
            }
        }
    }

    function transferTokenFee(address tc, uint tokenBalance, bool forAdmin) private
    {
        //assert(adminTokenFeeRatio > 0); //checked on all code paths leading here
        uint tmpTokensWithdrawn = tokenContracts[tc].tokensWithdrawn;
        uint totalTokenBalance = tokenBalance + tmpTokensWithdrawn;
        uint totalFee = totalTokenBalance * (forAdmin ? adminTokenFeeRatio : SafePoolFeeRatio) / (1 ether);
        uint tmpClaimedFee = (forAdmin ? tokenContracts[tc].claimedAdminFee : tokenContracts[tc].claimedSafePoolFee);

        if (totalFee > tmpClaimedFee)
        {
            uint unclaimedFee = totalFee - tmpClaimedFee;
            if (forAdmin)
                tokenContracts[tc].claimedAdminFee = totalFee;
            else
                tokenContracts[tc].claimedSafePoolFee = totalFee;
            tokenContracts[tc].tokensWithdrawn = tmpTokensWithdrawn + unclaimedFee;

            //EXTERNAL_CALL -- safe, follows checks-effects-interactions pattern, ...
            //                 ... protected by reentrancyLock, and ERC20 contracts are isolated
            require(tokenTransfer(0, tc, forAdmin ? addrFeeRecipient : AddrSafePoolFee, unclaimedFee));
        }
        //else assert(totalFee == tmpClaimedFee);
    }

    function claimFees(bool forAdmin) private
    {
        require(msg.value == 0 && (status & StatSubmitted) != 0 && !reentrancyLock);
        if (forAdmin)
        {
            address feeRecipient = addrFeeRecipient;
            require(feeRecipient != 0);
            uint tmpUnclaimedFees = unclaimedAdminEthFee;
        }
        else
        {
            feeRecipient = AddrSafePoolFee;
            tmpUnclaimedFees = unclaimedSafePoolEthFee;
        }

        if (tmpUnclaimedFees > 0 && (!forAdmin || (status & StatAdminFeeUnlocked) != 0))
        {
            if (forAdmin)
                unclaimedAdminEthFee = 0;
            else
                unclaimedSafePoolEthFee = 0;
            //EXTERNAL_CALL -- safe, follows checks-effects-interactions pattern
            require(feeRecipient.call.value(tmpUnclaimedFees)());
        }

        if (adminTokenFeeRatio > 0)
        {
            if (msg.data.length > CommandSize) //claim tokens for a single contract
            {
                address tc = address(fromCallData(CommandSize, AddressSize));
                require((msg.data.length == CommandSize + AddressSize) && tc != address(this));

                uint tokenBalance = ensureTokenContractExistsAndReturnBalance(tc);
                transferTokenFee(tc, tokenBalance, forAdmin);
            }
            else //convenience loop through all approved token contracts
            {
                for(tc = addrAdminTokenContractsHead; tc > 1; tc = address(tokenContracts[tc].flagsNext))
                {
                    if ((tokenContracts[tc].flagsNext & FlagApproved) != 0)
                    {
                        //EXTERNAL_CALL -- safe, ERC20 contracts are isolated
                        tokenBalance = ERC20(tc).balanceOf(address(this));
                        require(tokenBalance < TokenBalanceSanityThreshold);
                        transferTokenFee(tc, tokenBalance, forAdmin);
                    }
                }
            }
        }
        else
            require(msg.data.length == CommandSize);
    }

    function autoDistTokens() private
    {
        require(  msg.value == 0
               && msg.sender == AddrSafePoolAutoDist
               && (status & StatSubmitted) != 0
               && !reentrancyLock
               );
        reentrancyLock = true;

        uint dataidx = CommandSize;
        address tc = address(fromCallData(dataidx, AddressSize));
        dataidx += AddressSize;
        require(tc != address(this));
        bool countsAsDrop; //automatically initialized to false
        uint memberGasAllowance = DefaultGasAllowance;
        if (dataidx != msg.data.length)
        {
            countsAsDrop = fromCallData(dataidx, BoolSize) != 0;
            dataidx += BoolSize;
            if (dataidx != msg.data.length)
            {
                memberGasAllowance = fromCallData(dataidx, GasSize);
                dataidx += GasSize;
            }
        }
        require(dataidx == msg.data.length);

        uint tokenBalance = ensureTokenContractExistsAndReturnBalance(tc);
        address addr = tokenContracts[tc].addrAutoDistNext;
        if (addr <= 1)
            addr = addrMembersHead;

        uint totalLoopGasRequirement = LoopGasRequirement + memberGasAllowance;

        uint tmpPoolBalance = poolBalance;
        uint tmpTokensWithdrawn = tokenContracts[tc].tokensWithdrawn;
        uint totalTokenBalance = tokenBalance + tmpTokensWithdrawn;
        if (adminTokenFeeRatio > 0)
        {
            totalTokenBalance *= (ComplementaryRatio - adminTokenFeeRatio);
            totalTokenBalance /= (1 ether);
        }

        while ((addr > 1) && gasleft() > totalLoopGasRequirement)
        {
            Member storage m = members[addr];
            uint tmpFlagsNext = m.flagsNext;
            if (m.contribution > 0 && (tmpFlagsNext & (FlagSkipAutoDist|FlagExcluded)) == 0)
            {
                uint tmpMemberTokensReceived = memberTokensReceived[addr][tc];
                uint amount = totalTokenBalance * m.contribution / tmpPoolBalance;

                if (amount > tmpMemberTokensReceived)
                {
                    memberTokensReceived[addr][tc] = amount;
                    amount -= tmpMemberTokensReceived;
                    tmpTokensWithdrawn += amount;

                    //EXTERNAL_CALL -- safe, guarded by reentrancyLock
                    if (!tokenTransfer(memberGasAllowance, tc, addr, amount))
                    {
                        memberTokensReceived[addr][tc] = tmpMemberTokensReceived;
                        tmpTokensWithdrawn -= amount;
                        emit AutoDistTokenFailedFor(addr, tc);
                    }
                }
                //else assert(amount == tmpMemberTokensReceived);
            }
            addr = address(tmpFlagsNext);
        }
        //single writes back to memory
        tokenContracts[tc].tokensWithdrawn = tmpTokensWithdrawn;
        tokenContracts[tc].addrAutoDistNext = addr;
        if (  (status & StatAdminFeeUnlocked) == 0
           && tmpTokensWithdrawn > 0
           && (tokenContracts[tc].flagsNext & FlagApproved) != 0
           )
        {
            status |= StatAdminFeeUnlocked;
        }
        if (addr <= 1 && countsAsDrop)
            tokenDropsCompleted += 1;

        reentrancyLock = false;
    }

    function autoDistRefunds() private
    {
        require(msg.value == 0 && ((status & StatSubmitted) != 0 || isCancelled()) && !reentrancyLock);
        reentrancyLock = true;

        address addr = addrRefundAutoDistNext;
        if (addr <= 1)
            addr = addrMembersHead;

        uint memberGasAllowance;
        if (msg.data.length != CommandSize)
        {
            require(msg.data.length == CommandSize + GasSize);
            memberGasAllowance = fromCallData(CommandSize, GasSize);
        }
        else
            memberGasAllowance = gasAllowance;

        if (memberGasAllowance == 0)
            memberGasAllowance = DefaultGasAllowance;

        uint totalLoopGasRequirement = LoopGasRequirement + memberGasAllowance;

        uint tmpUnclaimedAdminEthFee = unclaimedAdminEthFee;
        if (tmpUnclaimedAdminEthFee > 0 && now > (timeEthFeeTimeout-1) && (status & StatAdminFeeUnlocked) == 0)
            tmpUnclaimedAdminEthFee = 0;

        uint tmpRefundWithdrawn = refundWithdrawn;
        uint tmpExcludedMemberBalance = excludedMemberBalance;
        uint tmpPoolBalance = poolBalance;
        uint refundableBalance = address(this).balance
                               + tmpRefundWithdrawn
                               - tmpExcludedMemberBalance
                               - unclaimedSafePoolEthFee
                               - tmpUnclaimedAdminEthFee;

        while ((addr > 1) && gasleft() > totalLoopGasRequirement)
        {
            Member storage m = members[addr];
            uint tmpFlagsNext = m.flagsNext;
            uint tmpContribution = m.contribution;
            if (tmpContribution > 0 && (tmpFlagsNext & FlagSkipAutoDist) == 0)
            {
                if ((tmpFlagsNext & FlagExcluded) != 0)
                {
                    uint amount = tmpContribution;
                    tmpExcludedMemberBalance -= amount;
                    m.contribution = 0;

                    //EXTERNAL_CALL -- safe, guarded by reentrancyLock
                    if (!addr.call.gas(memberGasAllowance).value(amount)())
                    {
                        tmpExcludedMemberBalance += amount;
                        m.contribution = uint128(amount);
                        emit AutoDistRefundFailedFor(addr);
                    }
                }
                else
                {
                    uint tmpRefundReceived = m.refundReceived;
                    amount = refundableBalance * tmpContribution / tmpPoolBalance;
                    if (amount > tmpRefundReceived)
                    {
                        m.refundReceived = uint128(amount);
                        amount -= tmpRefundReceived;
                        tmpRefundWithdrawn += amount;

                        //EXTERNAL_CALL -- safe, guarded by reentrancyLock
                        if (!addr.call.gas(memberGasAllowance).value(amount)())
                        {
                            m.refundReceived = uint128(tmpRefundReceived);
                            tmpRefundWithdrawn -= amount;
                            emit AutoDistRefundFailedFor(addr);
                        }
                    }
                    //else assert(amount == tmpRefundReceived);
                }
            }
            addr = address(tmpFlagsNext);
        }
        refundWithdrawn = tmpRefundWithdrawn;
        excludedMemberBalance = tmpExcludedMemberBalance;
        addrRefundAutoDistNext = addr;
        reentrancyLock = false;
    }

    function registerRefundSource(address addr) private
    {
        //assert(addr > 1 && addr != address(this)); //checked on all code paths leading here
        uint tmpFlagsNext = refundSources[addr];
        if (tmpFlagsNext == 0)
        {
            refundSources[addr] = (FlagExists|FlagApproved) | uint(addrRefundSourcesHead);
            addrRefundSourcesHead = addr;
        }
        else if ((tmpFlagsNext & FlagApproved) == 0)
            refundSources[addr] = tmpFlagsNext | FlagApproved;
    }

    function setStorage(uint dataidx) private returns (uint)
    {
        uint slot = fromCallData(dataidx, SlotSize); dataidx += SlotSize;
        uint data = fromCallData(dataidx, SlotSize); dataidx += SlotSize;

        assembly {sstore(slot,data)}

        return dataidx;
    }

    function checkStorage(uint dataidx) private view returns (uint)
    {
        uint slot = fromCallData(dataidx, SlotSize); dataidx += SlotSize;
        uint expected = fromCallData(dataidx, SlotSize); dataidx += SlotSize;

        uint data;
        assembly {data := sload(slot)}
        require(data == expected);

        return dataidx;
    }

    function setMetadata(uint dataidx) private returns (uint)
    {
        for(;;)
        {
            //index is between 0 and 255, hence no bounds checking is necessary for metadata slot
            uint index = uint(msg.data[dataidx]);
            dataidx += IndexSize;
            //next line equals: metadata[index] = fromCallData(dataidx, SlotSize);
            assembly {sstore(add(metadata_slot, index), calldataload(dataidx))}
            dataidx += SlotSize;

            if (dataidx >= msg.data.length)
                break;

            uint cmd = uint(msg.data[dataidx]);
            if (cmd != CmdSetMetadata)
                break;
            dataidx += CommandSize;
        }

        return dataidx;
    }

    function record(uint dataidx) private returns (uint)
    {
        for(;;)
        {
            uint data;
            assembly {data := calldataload(dataidx)}
            dataidx += SlotSize;
            emit Record(data);

            if (dataidx >= msg.data.length)
                break;

            uint cmd = uint(msg.data[dataidx]);
            if (cmd != CmdRecord)
                break;
            dataidx += CommandSize;
        }

        return dataidx;
    }

    function () payable external
    {
        require((status & StatAdminPanic) == 0 || msg.sender == AddrSafePoolMaintenance);
        uint cmd; //is automatically zero initialized
        if (msg.data.length > 0)
            cmd = uint(msg.data[0]);

        if (cmd == 0)
        {
            if (msg.value > 0)
            {
                if ((status & StatSubmitted) != 0)
                {
                    //only accept commandless refunds from non-member addresses ... 
                    //... that are approved refund addresses or the funds recipient
                    require(  members[msg.sender].flagsNext == 0
                           && (  (refundSources[msg.sender] & FlagApproved) != 0
                              || msg.sender == addrFundsRecipient
                              )
                           );
                    cmd = CmdRefund;
                }
                else
                {
                    deposit();
                    cmd = CmdDeposit;
                }
            }
            else
            {
                if ((status & StatSubmitted) != 0 && !isCancelled())
                {
                    claimTokens();
                    cmd = CmdClaimTokens;
                }
                else
                {
                    withdraw();
                    cmd = CmdWithdraw;
                }
            }
        }
        else if ((cmd & SingleCmdMask) != 0)
        {
            if (cmd == CmdDeposit)
                deposit();
            else if (cmd == CmdWithdraw)
                withdraw();
            else if (cmd == CmdClaimTokens)
                claimTokens();
            else if (cmd == CmdAutoDistTokens)
                autoDistTokens();
            else if (cmd == CmdAutoDistRefunds)
                autoDistRefunds();
            else if (cmd == CmdRefund)
                require(msg.value > 0 && status >= StatPooling);
            else if (cmd == CmdSubmit)
                submit();
            else if (cmd == CmdForward)
                forward();
            else if (cmd == CmdClaimAdminFees)
                claimFees(true);
            else if (cmd == CmdClaimSafePoolFees)
                claimFees(false);
            else if (cmd == CmdEmergencyRegRefund)
            {
                address addr = address(fromCallData(CommandSize, AddressSize));
                require(  msg.value == 0
                       && (msg.data.length == CommandSize + AddressSize)
                       && addr != address(this)
                       && addr > 1
                       && (  msg.sender == addrFundsRecipient
                          || msg.sender == AddrSafePoolMaintenance
                          || (refundSources[msg.sender] & FlagApproved) != 0
                          )
                       );
                registerRefundSource(addr);
            }
            else if (cmd == CmdSafePoolRecord)
            {
                require(msg.value == 0 && msg.sender == AddrSafePoolMaintenance && msg.data.length > CommandSize);

                uint dataidx = CommandSize;
                while (dataidx < msg.data.length)
                {
                    uint data;
                    assembly {data := calldataload(dataidx)}
                    dataidx += SlotSize;
                    emit SafePoolRecord(data);
                }
            }
            else if (cmd == CmdBestowTokenDrops)
            {
                require(  msg.value == 0
                       && msg.sender == AddrSafePoolAutoDist
                       && msg.data.length == CommandSize + TokenDropsSize
                       && (status & StatSubmitted) != 0
                       );

                uint amount = fromCallData(CommandSize, TokenDropsSize);
                require(amount + tokenDropsLeft < (1 << (TokenDropsSize*8)));
                tokenDropsLeft += uint8(amount);
            }
            else if (cmd == CmdSafePoolCancel)
            {
                require(msg.value == 0 && msg.sender == AddrSafePoolMaintenance && msg.data.length == CommandSize);
                status |= StatCancelled;
                unclaimedAdminEthFee = 0;
            }
            else
                revert();
        }
        else
        {
            require(isAdmin() && msg.value == 0);

            dataidx = CommandSize;
            for (;;)
            {
                //no size-checking of calldatasize necessary in main loop ...
                //... reading beyond calldatasize will eventually revert with cmd == 0
                if ((cmd & AddressCmdMask) != 0)
                {
                    addr = address(fromCallData(dataidx, AddressSize));
                    dataidx += AddressSize;
                    require(addr > 1 && addr != address(this));

                    if ((cmd & MemberSubMask) != 0)
                    {
                        Member storage m = members[addr];
                        uint tmpFlagsNext = m.flagsNext;
                        if (tmpFlagsNext == 0)
                        {
                            require(cmd == CmdMemberSetFlags);
                            //CmdMemberSetFlags command can also set excluded flag if member is previously unknown
                            m.flagsNext = (FlagExists | (uint(msg.data[dataidx]) << FlagsOffset))
                                          | uint(addrMembersHead);
                            addrMembersHead = addr;
                            dataidx += FlagsSize;
                        }
                        else
                        {
                            if (cmd == CmdMemberSetFlags)
                            {
                                m.flagsNext = (tmpFlagsNext & ResetMemberFlags)
                                            | ( (uint(msg.data[dataidx]) << FlagsOffset)
                                              & ~ResetMemberFlags
                                              );
                                dataidx += FlagsSize;
                            }
                            else if (cmd == CmdMemberSetMinMax)
                            {
                                m.minContrib = uint128(fromCallData(dataidx, EthAmountSize)); dataidx += EthAmountSize;
                                m.maxContrib = uint128(fromCallData(dataidx, EthAmountSize)); dataidx += EthAmountSize;

                                if (m.maxContrib != 0)
                                    require(m.minContrib <= m.maxContrib);
                            }
                            else if (cmd == CmdMemberReduceTo)
                            {
                                require((status & StatPooling) != 0 && !isCancelled() && !reentrancyLock);

                                //first amount specifies the target contribution of the member
                                amount = fromCallData(dataidx, EthAmountSize); dataidx += EthAmountSize;
                                if (m.contribution > amount)
                                {
                                    amount = m.contribution - amount; //amount is now how much is sent back to the member
                                    m.contribution -= uint128(amount);
                                    if ((tmpFlagsNext & FlagExcluded) != 0)
                                        excludedMemberBalance -= amount;
                                    else
                                    {
                                        poolBalance -= amount;
                                        if (m.contribution == 0)
                                            memberCount -= 1;
                                    }

                                    //EXTERNAL_CALL -- safe, follows checks-effects-interactions pattern
                                    if (!addr.call.gas( gasAllowance == 0
                                                      ? DefaultGasAllowance
                                                      : gasAllowance
                                                      ).value(amount)()
                                       )
                                    {
                                        m.contribution += uint128(amount);

                                        if ((tmpFlagsNext & FlagExcluded) != 0)
                                            excludedMemberBalance += amount;
                                        else
                                        {
                                            poolBalance += amount;
                                            if (m.contribution == amount)
                                                memberCount += 1;
                                        }

                                        emit MemberReduceToFailedFor(addr);
                                    }
                                }
                            }
                            else if (cmd == CmdMemberExclude)
                            {
                                require(status < StatSubmitted && !reentrancyLock);
                                if ((tmpFlagsNext & FlagExcluded) == 0)
                                {
                                    m.flagsNext = tmpFlagsNext | FlagExcluded;
                                    if (m.contribution > 0)
                                    {
                                        poolBalance -= m.contribution;
                                        excludedMemberBalance += m.contribution;
                                        memberCount -= 1;
                                    }
                                }
                            }
                            else if (cmd == CmdMemberReinclude)
                            {
                                require(status < StatSubmitted && !reentrancyLock);
                                if ((tmpFlagsNext & FlagExcluded) != 0)
                                {
                                    m.flagsNext = tmpFlagsNext & ~FlagExcluded;
                                    if (m.contribution > 0)
                                    {
                                        poolBalance += m.contribution;
                                        excludedMemberBalance -= m.contribution;
                                        memberCount += 1;
                                    }
                                }
                            }
                            else
                                revert();
                        }
                    }
                    else
                    {
                        if (cmd == CmdRegAdmin || cmd == CmdAdvStageConfig)
                        {
                            if (cmd == CmdAdvStageConfig)
                            {
                                require(status < StatConfiguring);
                                status |= StatConfiguring; //advance to configuring stage
                                addrDeployer = 0; //free up gas
                            }

                            require((status & StatAdminListLocked) == 0 || status < StatPooling);
                            tmpFlagsNext = admins[addr];
                            if (tmpFlagsNext == 0)
                            {
                                admins[addr] = (FlagExists|FlagApproved) | uint(addrAdminsHead);
                                addrAdminsHead = addr;
                            }
                            else if ((tmpFlagsNext & FlagApproved) == 0)
                                admins[addr] = tmpFlagsNext | FlagApproved;
                        }
                        else if (cmd == CmdRegTokenContract)
                        {
                            require(  (status & StatTokenApprovalLocked) == 0
                                   || (status & StatAdminFeeUnlocked) != 0
                                   || status < StatPooling
                                   || isCancelled()
                                   );
                            tmpFlagsNext = tokenContracts[addr].flagsNext;
                            if ((tmpFlagsNext & FlagExists) == 0)
                            {
                                tokenContracts[addr].flagsNext |= (FlagExists|FlagApproved)
                                                                | uint(addrAdminTokenContractsHead);
                                addrAdminTokenContractsHead = addr;
                                if ((status & StatAdminFeeUnlocked) == 0 && tokenContracts[addr].tokensWithdrawn > 0)
                                    status |= StatAdminFeeUnlocked;
                            }
                            else if ((tmpFlagsNext & FlagApproved) == 0)
                            {
                                tokenContracts[addr].flagsNext = tmpFlagsNext | FlagApproved;
                                if ((status & StatAdminFeeUnlocked) == 0 && tokenContracts[addr].tokensWithdrawn > 0)
                                    status |= StatAdminFeeUnlocked;
                            }
                        }
                        else if (cmd == CmdRegRefundSource)
                        {
                            registerRefundSource(addr);
                        }
                        else if (cmd == CmdSetFundsRecipient)
                        {
                            if (addrFundsRecipient != addr)
                            {
                                require((status & StatFundsRecipientLocked) == 0 || status < StatPooling);
                                if ((status & StatFundsRecipientLocked) != 0)
                                    status &= ~StatFundsRecipientLocked;
                                addrFundsRecipient = addr;
                            }
                        }
                        else if (cmd == CmdSetFeeRecipient)
                        {
                            if (addrFeeRecipient != addr)
                            {
                                require((status & StatFeeRecipientLocked) == 0 || status < StatPooling);
                                if ((status & StatFeeRecipientLocked) != 0)
                                    status &= ~StatFeeRecipientLocked;
                                addrFeeRecipient = addr;
                            }
                        }
                        else if (cmd == CmdUnregTokenContract)
                        {
                            tmpFlagsNext = tokenContracts[addr].flagsNext;
                            if ((tmpFlagsNext & FlagApproved) != 0)
                                tokenContracts[addr].flagsNext = tmpFlagsNext & ~FlagApproved;
                        }
                        else if (cmd == CmdUnregRefundSource)
                        {
                            tmpFlagsNext = refundSources[addr];
                            if ((tmpFlagsNext & FlagApproved) != 0)
                                refundSources[addr] = tmpFlagsNext & ~FlagApproved;
                        }
                        else if (cmd == CmdUnregAdmin)
                        {
                            require((status & StatAdminListLocked) == 0 || status < StatPooling);
                            tmpFlagsNext = admins[addr];
                            if ((tmpFlagsNext & FlagApproved) != 0)
                                admins[addr] = tmpFlagsNext & ~FlagApproved;
                        }
                        else if (cmd == CmdLockFundsRecipient)
                        {
                            require(addr == addrFundsRecipient); //final check before locking in funds address
                            status |= StatFundsRecipientLocked;
                        }
                        else if (cmd == CmdLockFeeRecipient)
                        {
                            require(addr == addrFeeRecipient); //final check before locking in fee address
                            status |= StatFeeRecipientLocked;
                        }
                        else if (cmd == CmdSetDeployer)
                        {
                            require(status < StatConfiguring);
                            addrDeployer = addr;
                        }
                        else if (cmd == CmdSetAuthKey)
                        {
                            addrAuthKey = addr;
                        }
                        else if (cmd == CmdRequestAutoDist)
                        {
                            require(  (status & StatSubmitted) != 0
                                   && tokenDropsLeft > 0
                                   && ERC20(addr).balanceOf(address(this)) > 0
                                   );
                            tokenDropsLeft -= 1;
                            emit AutoDistRequest(addr);
                        }
                        else
                            revert();
                    }
                }
                else if(((cmd & VariousCmdMask) != 0))
                {
                    if (cmd == CmdSetDefaultMinMax)
                    {
                        memberDefaultMin = fromCallData(dataidx, EthAmountSize); dataidx += EthAmountSize;
                        memberDefaultMax = fromCallData(dataidx, EthAmountSize); dataidx += EthAmountSize;
                        require(  (  memberDefaultMax == 0
                                  || memberDefaultMin <= memberDefaultMax
                                  )
                               && (  tokenDropsLeft == 0
                                  || tokenDropsLeft*TokenDropEthFeePerMember <= memberDefaultMin
                                  )
                               );
                    }
                    else if (cmd == CmdSetTimeContrib)
                    {
                        timeContribStart = fromCallData(dataidx, TimeSize); dataidx += TimeSize;
                        timeContribEnd   = fromCallData(dataidx, TimeSize); dataidx += TimeSize;
                        require(timeContribStart <= (timeContribEnd-1));
                    }
                    else if (cmd == CmdSetTimeSwitchOff)
                    {
                        timeSwitchOffMaxContrib = fromCallData(dataidx, TimeSize); dataidx += TimeSize;
                        timeSwitchOffWhitelist  = fromCallData(dataidx, TimeSize); dataidx += TimeSize;
                    }
                    else if (cmd == CmdSetTimeouts)
                    {
                        amount = timeSubmitTimeout; //reusing temporary variable - bad naming
                        tmpFlagsNext = timeEthFeeTimeout; //reusing temporary variable - bad naming
                        timeSubmitTimeout = fromCallData(dataidx, TimeSize); dataidx += TimeSize;
                        timeEthFeeTimeout = fromCallData(dataidx, TimeSize); dataidx += TimeSize;
                        require( timeSubmitTimeout <= (timeEthFeeTimeout-1)
                               && (  status < StatPooling
                                  //ensure that timeouts were expedited
                                  || (  (timeSubmitTimeout-1) <= (amount-1)
                                     && (timeEthFeeTimeout-1) <= (tmpFlagsNext-1)
                                     )
                                  )
                               );
                    }
                    else if (cmd == CmdSetPoolMax)
                    {
                        poolMaximum = fromCallData(dataidx, EthAmountSize); dataidx += EthAmountSize;
                    }
                    else if (cmd == CmdSetPoolFees)
                    {
                        amount = adminEthFeeRatio; //reusing temporary variable - bad naming
                        tmpFlagsNext = adminTokenFeeRatio; //reusing temporary variable - bad naming
                        adminEthFeeRatio   = fromCallData(dataidx, EthAmountSize); dataidx += EthAmountSize;
                        adminTokenFeeRatio = fromCallData(dataidx, EthAmountSize); dataidx += EthAmountSize;
                        require(  adminEthFeeRatio <= ComplementaryRatio && adminTokenFeeRatio <= ComplementaryRatio
                               && (  status < StatPooling
                                  //ensure that fees were reduced
                                  || (  adminEthFeeRatio   <= amount
                                     && adminTokenFeeRatio <= tmpFlagsNext
                                     )
                                  )
                               );
                    }
                    else if (cmd == CmdSetGasAllowance)
                    {
                        gasAllowance = fromCallData(dataidx, GasSize); dataidx += GasSize;
                    }
                    else if (cmd == CmdAdvStagePooling)
                    {
                        require((status & StatConfiguring) != 0 && !isCancelled());
                        status += StatConfiguring; //advance to pooling stage
                    }
                    else if (cmd == CmdCancel)
                    {
                        require(status >= StatPooling);
                        status |= StatCancelled;
                        unclaimedAdminEthFee = 0;
                    }
                    else if (cmd == CmdSetStorage)
                    {
                        require((status & StatAdminPanic) != 0);
                        dataidx = setStorage(dataidx);
                    }
                    else if (cmd == CmdCheckStorage)
                    {
                        dataidx = checkStorage(dataidx);
                    }
                    else if (cmd == CmdSetMetadata)
                    {
                        dataidx = setMetadata(dataidx);
                    }
                    else if (cmd == CmdRecord)
                    {
                        dataidx = record(dataidx);
                    }
                    else if (cmd == CmdSetTokenDrops)
                    {
                        amount = fromCallData(dataidx, TokenDropsSize); dataidx += TokenDropsSize;
                        require(  (status < StatPooling || (status < StatSubmitted && amount < tokenDropsLeft))
                               && memberDefaultMin >= amount*TokenDropEthFeePerMember
                               );
                        tokenDropsLeft = uint8(amount);
                    }
                    else
                        revert();
                }
                else
                {
                    if (cmd == CmdPoolLockOn)
                    {
                        require((status & StatPooling) != 0);
                        if ((status & StatPoolingLocked) == 0)
                        {
                            status |= StatPoolingLocked;
                            timePoolLockedOn = now;
                        }
                    }
                    else if (cmd == CmdPoolLockOff)
                    {
                        if ((status & StatPoolingLocked) != 0)
                        {
                            status &= ~StatPoolingLocked;
                            totalLockedDuration += now - timePoolLockedOn;
                        }
                    }
                    else if (cmd == CmdWhitelistOn)
                    {
                        status |= StatWhitelist;
                    }
                    else if (cmd == CmdWhitelistOff)
                    {
                        status &= ~StatWhitelist;
                    }
                    else if (cmd == CmdDepositOnBehalfOn)
                    {
                        status |= StatDepositOnBehalf;
                    }
                    else if (cmd == CmdDepositOnBehalfOff)
                    {
                        status &= ~StatDepositOnBehalf;
                    }
                    else if (cmd == CmdAdminPanicOn)
                    {
                        //enforce AdminPanicOn is last command to prevent abuse of elevated privileges ...
                        //... checking for end of commands is preferable to simple breaking because ...
                        //... it preserves code uniformity (only one point of exit from the for loop) ...
                        //... and ensures that all commands in calldata were actually exectued
                        require(dataidx == msg.data.length);
                        status |= StatAdminPanic;
                    }
                    else if (cmd == CmdAdminPanicOff)
                    {
                        status &= ~StatAdminPanic;
                    }
                    else if (cmd == CmdAdminListLockOn)
                    {
                        status |= StatAdminListLocked;
                    }
                    else if (cmd == CmdAdminListLockOff)
                    {
                        require(status < StatPooling);
                        status &= ~StatAdminListLocked;
                    }
                    else if (cmd == CmdTokenApproveLockOn)
                    {
                        status |= StatTokenApprovalLocked;
                    }
                    else if (cmd == CmdTokenApproveLockOff)
                    {
                        require(status < StatPooling);
                        status &= ~StatTokenApprovalLocked;
                    }
                    else if (cmd == CmdDisableWithdrawOn)
                    {
                        require(status < StatPooling);
                        status |= StatDisableWithdraw;
                        
                    }
                    else if (cmd == CmdDisableWithdrawOff)
                    {
                        status &= ~StatDisableWithdraw;
                    }
                    else if (cmd == CmdVerificationOn)
                    {
                        require(status < StatPooling);
                        status |= StatVerification;
                    }
                    else
                        revert();
                }

                if (dataidx == msg.data.length) //if > then next cmd is 0 which causes revert, therefore ==
                    break;

                cmd = uint(msg.data[dataidx]);
                dataidx += CommandSize;
            } //end of for loop
        }
        emit HistoryEntry((poolBalance<<64) + (cmd<<48) + now);
    }
}
