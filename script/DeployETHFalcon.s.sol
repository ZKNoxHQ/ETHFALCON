// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Script} from "../lib/forge-std/src/Script.sol";
import {BaseScript} from "./BaseScript.sol";
import "../src/ZKNOX_ethfalcon.sol";
import "../src/ZKNOX_falcon_deploy.sol";

import {console} from "forge-std/Test.sol";
//deploy the precomputed tables for psirev and psiInvrev

contract Script_Deploy_Falcon is BaseScript {
    // SPDX-License-Identifier: MIT

    function run() external {
        vm.startBroadcast();

        bytes32 salty = keccak256(abi.encodePacked("ZKNOX_v0.0.0.12"));
       
        ZKNOX_ethfalcon ETHFALCON = new ZKNOX_ethfalcon{salt: salty}();
       
        // public key in ntt form
        // forgefmt: disable-next-line
        uint256[32] memory tmp_pkc=[uint256(9807818718891730533966615164509575764017151053524099258423976834772553965140),18340098138125467691447337077959785268149994316939452976998993957504853156265,5198133703327284157071422809205815024336408019642137871855761911766001193757,885309680723773951581445950479448442138188963959751701993810286786334563851,19751655564167833205324936936214418086799632798155386652828683172706408935156,13449342659324330278443856651216754520591114337785977560380735844903743330507,21412685081650650572110719760616900735599281269400856811705495088893808813464,7182455876228287393000419492025555097227813236263190704105821148459893329094,10346702731445215087289400465904665036614373649415073766421551882524955579599,2602661461191686318241399797978336432747493635009153906211421228123447493354,17460152192629988224191839342813524149690975760517934797656766276578763941977,8030501380784039896959436505501001505082538439109709855711095179607370313313,1869334252111587522914549075648788783845949858255579782083590402809098144636,17244605423862552671483849252199675991941590481856488840270787535924580718702,11336265795525104660827282529254071061160673084427642199020414766362588092858,7834392541464967164445071157396824232455621343468123833119795953667476294495,19320749074383776626289869794062002119037822327089474229301777373758894647631,15804769950401279065265498737970159234892108086909038079651927057616326110849,5524941774629792613265643604106102575196474389604272009945361978094039402215,7912189081096546922096985544357356245951107957167270713824777693799477413938,9251517013408700470756725384748473476160720415021619476382719063671064631329,980629886819687668154444089811786886341348988887074213615781934824155389444,5940413397816454703448409408340853562548545866597888595192275835122337254858,3477241430632946704913201778186656752154449432278581298631128816987460934160,19684655324690250642900619926419342622662744597902662173890575167707890264962,21136817025198787960771334147393601715672137869525072998232149469960570804861,715695489957163697708304262996430301414652155424663974257962371003055997411,779487062625276624243092988713096201766390140956957709636694708471170673149,18108615907818392958604720912508457986590141052566906373861374637494342583430,4888923900533397196030088094647918125568719406578813186855259309838660932599,20133355404703468652353168553951350193203296046835794955257435485399706185274,6958150576137026963644397829477422234280792505821200919066265083919800276574];

        // signature s2
        // forgefmt: disable-next-line
        uint256[32] memory s2 = [uint256(290093910866615732134712510711399460403569264381710451764998993912354516987),23294688046888675336023881946381614331974127665022126442842278268369174637,496494728367860443245592910655546047867510078319673337469421111009636331468,7072920055862368565764904239260101619356553840776713116679213883866677270,21311709569988779015338503734400165559023680970741621653822586471153146527781,111312017109004435681040112255897123533766851930477384238258251916279164794,88670245098220810789487412484937713587720655688123478245382055077886504791,328964465442753307343779126311922999067172552121460590416686819674805645249,21502851192377344974677720091383491628103172940769909797141445589994887512387,5627920847635758858566843431442002562936947058222695711463693100139360100,21431857623681315288933966461423443819183840149553936598510141094328955830308,21513136250262619711231506136167889442562961681116045540186300404247453171889,157577033078164060199277775900361469822654466566183776269147086776893124336,83372211205253838500310696903816367141996568234385993087675719716688429116,353376988712210556848922668941644663928849762090033949381995016709698879621,21652712774031731141746166176420263113821164592915536277161025084583464415076,81598592217034589324780593611216049017701949159390610426608392358235275307,21509921039010805139733327459402746597020615583989782593635151589721612157114,21508158882908122413491952720591596305028555087993752742022272852636340584526,21407126423925543640874097367958078745413976612003616673797639326268766564228,150512804043819351386699326517228907284518001449880737190198073478267273438,21660100068921325183492252640798391213972113268072175023036821225677818310528,21486628669456466626254611453903485281968215437503649424454353073937687511334,21697210629161992372357118858950275018825639475949200247798747451646852595748,21644207805428569922450455380964932987166486980464183825652009273644620394411,404934435846955401297075594203959382460453070954769358588172502690697314471,74537571517205863809813961046887152101860084589476447069528187823956099261,38873439298323676235007618460019194991697800041752436004358538962083262383,173152958467187375232602546034444540495117769175691458023294445285913854076,21674237217903413808515430117098667542398170123325112962470901175538033307547,21679216639181971368260143510423269239492700569406357749179392013661296209879,70674880166754793750003755396911748946971220421867085467822785712871452594 ];

        ZKNOX_ethfalcon.CompactSignature memory sig;

        sig.s2 = new uint256[](32);
        uint256[] memory pkc = new uint256[](32);
        for (uint256 i = 0; i < 32; i++) {
            sig.s2[i] = s2[i];
            pkc[i] = tmp_pkc[i];
        }

        // message
        bytes memory message = "My name is Renaud";
        sig.salt =
            "\x35\x00\x31\x8f\x75\xad\x20\xf0\xaa\x20\x62\xba\x1c\x34\x8a\xfe\xaa\x49\x23\x87\xa4\x63\xeb\x8c\x28\xaf\x77\x9d\x6a\x3e\xa6\x96\xeb\xb9\x66\x0c\xcf\xf5\x06\x2d";

        bool result = ETHFALCON.verify(message, sig.salt, sig.s2, pkc);
        
        console.log("result:", result);

        if (result == false) revert("verification failure");

        vm.stopBroadcast();
    }
}
