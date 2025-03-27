// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Script} from "../lib/forge-std/src/Script.sol";
import {BaseScript} from "./BaseScript.sol";
import "../src/ZKNOX_falcon.sol";
import "../src/ZKNOX_falcon_deploy.sol";

import {console} from "forge-std/Test.sol";
//deploy the precomputed tables for psirev and psiInvrev

contract Script_Deploy_Falcon is BaseScript {
    // SPDX-License-Identifier: MIT

    function run() external {
        vm.startBroadcast();

        address a_psirev;
        address a_psiInvrev;
        bytes32 salty = keccak256(abi.encodePacked("ZKNOX_v0.0.0.20"));
        (a_psirev, a_psiInvrev) = Deploy(salty);

        ZKNOX_falcon FALCON = new ZKNOX_falcon{salt: salty}();
        FALCON.update(a_psirev, a_psiInvrev);

        // public key in ntt form
        // forgefmt: disable-next-line
        uint256[32] memory tmp_pkc = [9807818718891730533966615164509575764017151053524099258423976834772553965140, 18340098138125467691447337077959785268149994316939452976998993957504853156265, 5198133703327284157071422809205815024336408019642137871855761911766001193757, 885309680723773951581445950479448442138188963959751701993810286786334563851, 19751655564167833205324936936214418086799632798155386652828683172706408935156, 13449342659324330278443856651216754520591114337785977560380735844903743330507, 21412685081650650572110719760616900735599281269400856811705495088893808813464, 7182455876228287393000419492025555097227813236263190704105821148459893329094, 10346702731445215087289400465904665036614373649415073766421551882524955579599, 2602661461191686318241399797978336432747493635009153906211421228123447493354, 17460152192629988224191839342813524149690975760517934797656766276578763941977, 8030501380784039896959436505501001505082538439109709855711095179607370313313, 1869334252111587522914549075648788783845949858255579782083590402809098144636, 17244605423862552671483849252199675991941590481856488840270787535924580718702, 11336265795525104660827282529254071061160673084427642199020414766362588092858, 7834392541464967164445071157396824232455621343468123833119795953667476294495, 19320749074383776626289869794062002119037822327089474229301777373758894647631, 15804769950401279065265498737970159234892108086909038079651927057616326110849, 5524941774629792613265643604106102575196474389604272009945361978094039402215, 7912189081096546922096985544357356245951107957167270713824777693799477413938, 9251517013408700470756725384748473476160720415021619476382719063671064631329, 980629886819687668154444089811786886341348988887074213615781934824155389444, 5940413397816454703448409408340853562548545866597888595192275835122337254858, 3477241430632946704913201778186656752154449432278581298631128816987460934160, 19684655324690250642900619926419342622662744597902662173890575167707890264962, 21136817025198787960771334147393601715672137869525072998232149469960570804861, 715695489957163697708304262996430301414652155424663974257962371003055997411, 779487062625276624243092988713096201766390140956957709636694708471170673149, 18108615907818392958604720912508457986590141052566906373861374637494342583430, 4888923900533397196030088094647918125568719406578813186855259309838660932599, 20133355404703468652353168553951350193203296046835794955257435485399706185274, 6958150576137026963644397829477422234280792505821200919066265083919800276574];

        // signature s2
        // forgefmt: disable-next-line
        uint256[32] memory s2 = [21649177790571192151286347015496942774998047093443469911824293759971769921428, 268561837228003295750097962055377173144230591962156166013405983500166901722, 373131625068829243878329325423678131041649088938736656507320119997555081235, 21486956906798985719744375447418457093904022330284178432016463274856548335792, 21046685012579207363779083391328077072214150550607548013536002123977240477986, 21624441549379106406854913087313490894795813631028932379313967382686196510643, 21269307451108998178385520109334456835115990194191195737525785771781959909565, 21502531263687643325340175878774636041406187334634592429142727315400727670519, 21645644447053892427347704348572035349652711108703358737702992269605067960232, 21642434488002171509128269223391903377510003992725863045650229316731768864833, 143119470082566254482735508500984469699860060818744295831990820277956915152, 21329707513272854740751761229950211571450422559001525308753079369050633482098, 21274936790822894191602613586986915689519661452929637034834680332795904471016, 323334360936185288001981502514033468909440677622868552612107777952939454224, 123679299536821298309830082798375208376610949331800767508152351976155721432, 21491932279213207751766589616948004610084312966776105784769653908907333255233, 21555542660741624619295241800731825770453854520453475890665283178064948298017, 21221927933047296480928267470961179332618989116613413084747202280410795475009, 21640345869013883370330016229125346816596850570010888955143002957579576672404, 447342652619835196009820811808904031226531727490450346028265756926131110099, 48035216006736122407389636281329469805748676305369281203171327493607718987, 21518434450972238337302563984051994092825336572101022453461300155810011086937, 333938521709614508411251346141738162769014840087489168548614530158677590118, 21322638943617910190789463252175561671279485636811843560369873363276365299985, 67147494647851671533097211665243328708469268023218856658099323225006878424, 116612876865130439291083919507652316067243925780313881626436539371081498829, 21676008001193555476662926248472147257885449589381323941811680418544747741313, 127542681867544440369323810542605531185295482507825078859650437370710524036, 21474589727324966696397422730377349856660942504908738086594141842221836664953, 204955823209712158529229531556743920712069026834325166406926177293848227824, 55101682679218165125147635923326063419450638759116465378302788679604895838, 198216003314064520968126849996156841255555215727010889276036638293899030319];

        ZKNOX_falcon.CompactSignature memory sig;

        sig.s2 = new uint256[](32);
        uint256[] memory pkc = new uint256[](32);
        for (uint256 i = 0; i < 32; i++) {
            sig.s2[i] = s2[i];
            pkc[i] = tmp_pkc[i];
        }

        // message
        bytes memory message = "My name is Renaud";
        sig.salt =
            "\xab\x0b\xae\x31\x63\x39\x89\x43\x04\xe3\x58\x77\xb0\xc2\x8a\x9b\x1f\xd1\x66\xc7\x96\xb9\xcc\x25\x8a\x06\x4a\x8f\x57\xe2\x7f\x2a\x5b\x8d\x54\x8a\x72\x8c\x94\x44";

        bool result = FALCON.verify(message, sig.salt, sig.s2, pkc);
        if (result == true) {
            FALCON.setflag(uint256(1));
        }

        console.log("result:", result);

        if (result == false) revert("verification failure");

        vm.stopBroadcast();
    }
}
