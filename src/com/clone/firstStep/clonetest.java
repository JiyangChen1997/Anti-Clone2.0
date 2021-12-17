package com.clone.firstStep;


public class clonetest {
    public static void main(String[] args) {
        Parameter param = new Parameter();
        MD5 md5 = new MD5();
        user user = new user(param);
        server server = new server(param);
        Return2 re2 = new Return2();
        zkproof spk = null;
        zkproof22 ZPK22 = null;
        spk = user.generateSPK();
        System.out.println("the result of the first proof = "+server.verify(spk));
        Return11 re1 = server.genenrateRe(spk);                                     //生成joining阶段的零知识证明
        if (user.verifyRe(re1)){
            user.A = re1.A;
            user.y = re1.y;
            user.setT(re1.t2);
        }                                                                           //joining 阶段结束
        System.out.println("=============================\n\n\n");
        server.receiveZkproof21(user.generateSPK21());                              //生成认证阶段的零知识证明第一步
        user.receiveChallenge(server.generateChallenge());
        ZPK22 = user.generateSPK22();                                               //第二步
        server.receiveZkproof22(ZPK22);
        if (! server.verifspk2()) {                                                 //验证零知识证明
            System.out.println("spk2 false");
        } else if (! server.verifyS()){
            System.out.println("verify S false");                                   //验证 S
        } else if (! server.verifyR() ){
            System.out.println("verify R false");                                   //验证 R
        } else if (! server.verifySN()){
            System.out.println("verify SN false");                                  //验证 SN
        } else {
            System.out.println( "the second proof verifies true!");
        }                                                   //第二阶段结束
        re2 = server.genenrateRe2();                                                //用户登出
        System.out.println(user.verifyRe2(re2));
        System.out.println(server.generateY());
//        server.generateAllSN(user.s,user.t);              //撤销恶意用户
    }
}
