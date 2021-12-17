package com.clone.firstStep;

import java.math.BigInteger;
import java.util.Random;
import java.util.Vector;

public class server {
    Parameter param;                                                                                            //public params
    zkproof21 zkProof21;                                                                                        //received messages in the first step of the second proof
    zkproof22 zpk22;                                                                                            //received messages in the second step of the second proof
    BigInteger challenge;                                                                                       //challenge
    Vector<BigInteger> bigIntegers = new Vector<>(16);                                              //s
    BigInteger A_;
    BigInteger T;
    BigInteger T1;
    BigInteger T2;
    BigInteger ic;
    BigInteger SN;
    BigInteger D;
    BigInteger R1;
    BigInteger R2;
    public server(Parameter parameter) {                                                                        //constructor of server
        this.param = parameter;
    }
    public boolean verify(zkproof spk){                                                                         //verify the first zkproof
        BigInteger numc = new BigInteger(spk.c);
        Vector<BigInteger> bigIntegers = new Vector<>();
        MD5 md5 = new MD5();
        BigInteger p1_;
        BigInteger p2_;
        BigInteger p3_;
        String c_ = "";
        c_ += param.B.toString()+param.Qrn.A.toString()+param.Qrn.Ax.toString()+param.Qrn.As.toString()+param.Qrn.At.toString()+
                param.Qrn.Ai.toString()+param.Qrn.Ae.toString()+param.Qrn.Ad.toString()+param.Qrn.h.toString();
        for (int i = 0; i < 3; i++) {
            c_ += spk.y.elementAt(i);
        }
        for (int i = 0; i < spk.s.size(); i++) {
            bigIntegers.add(new BigInteger(spk.s.elementAt(i)));
        }
        p1_ = new BigInteger(spk.y.elementAt(0)).modPow(numc,param.Sigma).multiply(param.B.                         //PKU
                modPow(bigIntegers.elementAt(0),param.Sigma)).mod(param.Sigma);
        p2_ = new BigInteger(spk.y.elementAt(1)).modPow(numc,param.Sigma).multiply(param.B.                         //J1
                modPow(bigIntegers.elementAt(1),param.Sigma)).mod(param.Sigma);
        p3_ = new BigInteger(spk.y.elementAt(2)).modPow(numc,param.N);                                              //J2
        p3_ =p3_.multiply(param.Qrn.Ax.modPow(bigIntegers.elementAt(2),param.N)).mod(param.N);
        p3_ = p3_.multiply(param.Qrn.As.modPow(bigIntegers.elementAt(3),param.N)).mod(param.N);
        p3_ = p3_.multiply(param.Qrn.At.modPow(bigIntegers.elementAt(4),param.N)).mod(param.N);
        p3_ = p3_.multiply(param.Qrn.Ai.modPow(bigIntegers.elementAt(5),param.N)).mod(param.N);
        p3_ = p3_.multiply(param.Qrn.Ae.modPow(bigIntegers.elementAt(6),param.N)).mod(param.N);
        p3_ = p3_.multiply(param.Qrn.Ad.modPow(bigIntegers.elementAt(7),param.N)).mod(param.N);
        p3_ = p3_.multiply(param.Qrn.h.modPow(bigIntegers.elementAt(8),param.N)).mod(param.N);
        p3_ = p3_.multiply(param.Qrn.A).mod(param.N);
        c_ += p1_.toString() + p2_.toString() + p3_.toString();
        c_ = md5.start(c_);
        c_ = new BigInteger(c_,16).toString(2).substring(0,param.k-1);
        c_ = new BigInteger(c_,2).toString();
        return spk.c.equals(c_);
    }
    public Return11 genenrateRe(zkproof spk){                                                                     //generate A y t2 as returned result to user
        Return11 re = new Return11();
        re.t2 = generateNum.generateNum(70);                                                                //generate t2
        if (re.t2.mod(Parameter.bigTwo).equals(Parameter.bigZero)){                                                 //confirm that t2 is odd
            re.t2 = re.t2.add(Parameter.bigOne);
        }
        re.y = generateY();                                                              //generate y
        BigInteger y_inv;
        y_inv = re.y.modInverse(param.OrderN);
        BigInteger J2 = new BigInteger(spk.y.elementAt(2)).multiply(param.Qrn.A).mod(param.N);
        BigInteger tempA = J2.multiply(param.Qrn.At.modPow(re.t2,param.N)).mod(param.N);
        re.A = tempA.modPow(y_inv,param.N);                                                                         //generate A
        return re;


    }
    public BigInteger generateChallenge(){                                                                              //generate challenge
        challenge = generateNum.generateNum(70);
        return challenge;
    }
    public void receiveZkproof21(zkproof21 zkpf21){
        zkProof21 = zkpf21;
    }
    public void receiveZkproof22(zkproof22 zkpf22){
        zpk22 = zkpf22;
        R1 = new BigInteger(zpk22.R1);
        R2 = new BigInteger(zpk22.R2);
    }
    public boolean verifspk2(){
        String c_ = "";
        c_ += challenge.toString() + zkProof21.A_ + zkProof21.T + zkProof21.ic + zkProof21.SN + zkProof21.D
                + zkProof21.T1 + zkProof21.T2;
        BigInteger numc = new BigInteger(zpk22.c);
        for (int i = 0; i < zpk22.s.size(); i++) {
            bigIntegers.add(new BigInteger(zpk22.s.elementAt(i)));
        }
        A_ = new BigInteger(zkProof21.A_);
        T = new BigInteger(zkProof21.T);
        T1 = new BigInteger(zkProof21.T1);
        T2 = new BigInteger(zkProof21.T2);
        ic = new BigInteger(zkProof21.ic);
        SN = new BigInteger(zkProof21.SN);
        D = new BigInteger(zkProof21.D);
        boolean flag = zkProof21.flag;
        BigInteger p11 = param.Qrn.A.modPow(numc,param.N).multiply(A_.modPow(bigIntegers.elementAt(0)               //a^(c)*A'^(s1-c*2^(gama)) mod n
                .subtract(numc.multiply(Parameter.bigTwo.pow(210))),param.N)).mod(param.N);
        BigInteger p12 = param.Qrn.Ax.modPow(bigIntegers.elementAt(1),param.N);                                     //ax^(s2)*as^(s3)*at^(s4)*ai^(s5)*ae^(s6)*ad^(s7)*h^(s8) mod n
        p12 = p12.multiply(param.Qrn.As.modPow(bigIntegers.elementAt(2),param.N)).mod(param.N);
        p12 = p12.multiply(param.Qrn.At.modPow(bigIntegers.elementAt(3),param.N)).mod(param.N);
        p12 = p12.multiply(param.Qrn.Ai.modPow(bigIntegers.elementAt(4),param.N)).mod(param.N);
        p12 = p12.multiply(param.Qrn.Ae.modPow(bigIntegers.elementAt(5),param.N)).mod(param.N);
        p12 = p12.multiply(param.Qrn.Ad.modPow(bigIntegers.elementAt(6),param.N)).mod(param.N);
        p12 = p12.multiply(param.Qrn.h.modPow(bigIntegers.elementAt(7),param.N)).mod(param.N);
        BigInteger p1 = p11.multiply(p12.modInverse(param.N)).mod(param.N);                                                 //p1 = p11*p12 mod n
        BigInteger p2 = T.modPow(numc,param.Sigma).multiply(param.B1.modPow(bigIntegers.elementAt(3),param.Sigma))    //p2 = T^(c) * b1^(s4)*b2^(s9) mod sigma
                .multiply(param.B2.modPow(bigIntegers.elementAt(8),param.Sigma)).mod(param.Sigma);
        BigInteger p3 = T1.modPow(numc,param.Sigma).multiply(param.B1.modPow(bigIntegers.elementAt(4),param.Sigma))   //p3 = T1^(c) * b1^(s5) * b2^(s10) mod sigma
                .multiply(param.B2.modPow(bigIntegers.elementAt(9),param.Sigma)).mod(param.Sigma);
        BigInteger p4 = T2.modPow(numc,param.Sigma).multiply(T1.modPow(bigIntegers.elementAt(5),param.Sigma)).mod(param.Sigma);//p4 = T2^(c) * T1^(s6) mod sigma
        BigInteger p5 = T2.modPow(numc,param.Sigma).multiply(param.B1.modPow(bigIntegers.elementAt(10),param.Sigma))            //p5 = T2^(c)*b1^(s11)*b2^(s12) mod sigma
                .multiply(param.B2.modPow(bigIntegers.elementAt(11),param.Sigma)).mod(param.Sigma);
        BigInteger p61 = bigIntegers.elementAt(12).subtract(bigIntegers.elementAt(5).add(bigIntegers.elementAt(6))).mod(param.K_at);
        BigInteger p6 = param.B.modPow(p61,param.Sigma);                                                                              //p6 = b^(s13)/(b^(s6)*b^(s7)) mod sigma
        BigInteger p71;
        if (flag == false){
            p71 = numc.add(ic.multiply(bigIntegers.elementAt(5))).subtract(bigIntegers.elementAt(10)
                    .subtract(param.K_at.multiply(bigIntegers.elementAt(13)))).mod(param.K_at);                                 //p71 = c+ic*s6 - s11-K_at * s14
        } else {
            p71 = numc.add(ic.multiply(bigIntegers.elementAt(5))).subtract(bigIntegers.elementAt(10)
                    .subtract(param.K_at.multiply(bigIntegers.elementAt(13))).add(bigIntegers.elementAt(5))).mod(param.K_at);                            //p71 = c+ic*s6 - s11-K_at * s14 -s6
        }

        BigInteger p7 = param.Qrn.A.modPow(p71,param.N);                                                                               //p7 = a ^(p71) mod n
        BigInteger p81 = param.B1.modPow(numc,param.Sigma);
        BigInteger p821 = bigIntegers.elementAt(2).subtract(numc.multiply(ic));
        BigInteger p822 = p821.mod(param.OrderSignma);
        BigInteger p82 = SN.modPow(p822,param.Sigma);
        BigInteger p83 = param.B2.modPow(bigIntegers.elementAt(14),param.Sigma).modInverse(param.Sigma);
        BigInteger p8 = p81.multiply(p82).mod(param.Sigma).multiply(p83).mod(param.Sigma);                                              //p8 = (b1/(SN^(ic)))^(c)*SN^(s3)/(b2^(s15)) mod sigma

        BigInteger p91 = param.B2.modPow(numc,param.Sigma);
        BigInteger p921 = bigIntegers.elementAt(3).subtract(numc.multiply(ic));
        BigInteger p922 = p921.mod(param.OrderSignma);
        BigInteger p92 = SN.modPow(p922,param.Sigma);
        BigInteger p93 = param.B1.modPow(bigIntegers.elementAt(15),param.Sigma).modInverse(param.Sigma);
        BigInteger p9 = p91.multiply(p92).mod(param.Sigma).multiply(p93).mod(param.Sigma);                                              //p9 = (b2/(SN^(ic)))^(c)*SN^(s4)/(b2^(s16)) mod sigma

        BigInteger p101 = param.Qrn.A.multiply(param.Qrn.Ai.modPow(ic,param.N)).mod(param.N).modInverse(param.N);
        BigInteger p102 = D.multiply(p101).mod(param.N).modPow(numc,param.N);
        BigInteger p103 = param.Qrn.Ax.modPow(bigIntegers.elementAt(1),param.N);
        p103 = p103.multiply(param.Qrn.As.modPow(bigIntegers.elementAt(2),param.N)).mod(param.N);
        p103 = p103.multiply(param.Qrn.At.modPow(bigIntegers.elementAt(3),param.N)).mod(param.N);
        p103 = p103.multiply(param.Qrn.Ae.modPow(bigIntegers.elementAt(12),param.N)).mod(param.N);
        p103 = p103.multiply(param.Qrn.Ad.modPow(bigIntegers.elementAt(6),param.N)).mod(param.N);
        p103 = p103.multiply(param.Qrn.h.modPow(bigIntegers.elementAt(7),param.N)).mod(param.N);
        BigInteger p10 = p102.multiply(p103).mod(param.N);                                                                              //p10 = (D/(a*ai^(ic)))^(c)*ax^(s2)*as^(s3)*at^(s4)*ae^(s13)*ad^(s7)*h^(s8)mod n
        c_ = c_ + p1.toString() + p2.toString() + p3.toString() + p4.toString() + p5.toString()
                + p6.toString() + p7.toString() + p8.toString() + p9.toString() + p10.toString();

        MD5 md5 = new MD5();
        c_ = md5.start(c_);
        c_ = new BigInteger(c_,16).toString(2).substring(0,param.k-1);//可以优化
        c_ = new BigInteger(c_,2).toString();
        return zpk22.c.equals(c_);
    }
    public boolean verifyS(){
        if (!(verifyEpLamK(bigIntegers.elementAt(0)) && verifyEpLamK(bigIntegers.elementAt(1)) && verifyEpLamK(bigIntegers.elementAt(3))
            && verifyEpLamK(bigIntegers.elementAt(8)) && verifyEpLamK(bigIntegers.elementAt(9)))) {
            System.out.println("verify 201 false");
            return false;
        }
        if (!(verifyEpLsigK(bigIntegers.elementAt(2)))){
            System.out.println("verify 397 false");
            return false;
        }
        if (!(verifyEpLK(bigIntegers.elementAt(4)) && verifyEpLK(bigIntegers.elementAt(5)) && verifyEpLK(bigIntegers.elementAt(6))
                && verifyEpLK(bigIntegers.elementAt(12)) && verifyEpLK(bigIntegers.elementAt(13)))) {
            System.out.println("verify 111 false");
            return false;
        }
        if (!(verifyEpGamaLamK(bigIntegers.elementAt(7)))){
            System.out.println("verify 507 false");
            return false;
        }
        if (!(verifyEpDoulK(bigIntegers.elementAt(10)))){
            System.out.println("verify 126 false");
            return false;
        }
        if (!(verifyEpLamLK(bigIntegers.elementAt(11)))){
            System.out.println("verify 216 false");
            return false;
        }
        if (!(verifyEpDouLsigK(bigIntegers.elementAt(14)) && verifyEpDouLsigK(bigIntegers.elementAt(15)))){
            System.out.println("verify 699 false");
            return false;
        }
        return true;

    }                                      //verify S
    public boolean verifyR(){
//        if (R1.compareTo(param.Range5left)==1 && R1.compareTo(param.Range5right)==-1 &&
//                R2.compareTo(param.Range5left)==1 && R2.compareTo(param.Range5right)==-1){
//            System.out.println("R1 == "+R1);
//            System.out.println("R2 == "+R2);
//            System.out.println(param.Range5left);
//            System.out.println(param.Range5right);
//            System.out.println(param.OrderSignma);
//            return false;
//        }
        if (!(R1.compareTo(param.Range5left)== 1)){
            System.out.println("R1 left false");
            return false;
        }
        if (!(R2.compareTo(param.Range5left)== 1)){
            System.out.println("R2 left false");
            return false;
        }
        if (!(R1.compareTo(param.Range5right)== -1)){
            System.out.println("R1 right false");
            return false;
        }
        if (!(R2.compareTo(param.Range5right)== -1)){
            System.out.println("R2 right false");
            return false;
        }
        return true;
    }                                      //verify R
    public boolean verifySN(){
        BigInteger numc = new BigInteger(zpk22.c);
        BigInteger SN_ = T.modPow(numc,param.Sigma).multiply(param.B1.modPow(R1,param.Sigma)).mod(param.Sigma)
                .multiply(param.B2.modPow(R2,param.Sigma)).mod(param.Sigma);
        return SN.equals(SN_);
    }                                     //verify SN
    public boolean verifyEpLamK(BigInteger S){
        if (S.bitLength() == param.EpisilonLamK){
            return true;
        } else{
            System.out.println(S.bitLength());
            return false;
        }
    }
    public boolean verifyEpLsigK(BigInteger S){
        if (S.bitLength() == param.EpisilonLsigmaK){
            return true;
        } else{
            System.out.println(S.bitLength());
            return false;
        }
    }
    public boolean verifyEpLK(BigInteger S){
        if (S.bitLength() == param.EpisilonLK){
            return true;
        } else{
            System.out.println(S.bitLength());
            return false;
        }
    }
    public boolean verifyEpGamaLamK(BigInteger S){
        if (S.bitLength() == param.EpisilonGamaLamK){
            return true;
        } else{
            System.out.println(S.bitLength());
            return false;
        }
    }
    public boolean verifyEpDoulK(BigInteger S){
        if (S.bitLength() == param.EpisilonDoulK){
            return true;
        } else{
            System.out.println(S.bitLength());
            return false;
        }
    }
    public boolean verifyEpLamLK(BigInteger S){
        if (S.bitLength() == param.EpisilonLamLK){
            return true;
        } else{
            System.out.println(S.bitLength());
            return false;
        }
    }
    public boolean verifyEpDouLsigK(BigInteger S){
        if (S.bitLength() == param.EpisilonDouLsigK){
            return true;
        } else{
            System.out.println(param.EpisilonDouLsigK);
            System.out.println(S.bitLength());
            return false;
        }
    }
    public Return2 genenrateRe2(){                                 //generate AD,y'
        Return2 re = new Return2();
        re.y_ = generateY();
        BigInteger y_inv;
        y_inv = re.y_.modInverse(param.OrderN);
        re.AD = D.modPow(y_inv,param.N);
        return re;
    }
    public BigInteger generateY(){
        //    public BigInteger Range4left ;//2^gama-2^lamtha
        //    public BigInteger Range4right ;//2^gama+2^lamtha
        Random random = new Random();
        BigInteger randy = new BigInteger(Parameter.Lamtha+1,random);
        BigInteger y = param.Range4left.add(randy);
        while (!y.isProbablePrime(100)){
            randy = new BigInteger(Parameter.Lamtha+1,random);
            y = param.Range4left.add(randy);
        }
        return y;
    }
    public void generateAllSN(BigInteger s, BigInteger t){                                                                        // generate all user's SN when user is dishonest
        for (int i = 1; i < 1021; i = i+2) {
            BigInteger bigi = BigInteger.valueOf(i);
            BigInteger is_inv = bigi.add(s).modInverse(param.OrderSignma);
            BigInteger it_inv = bigi.add(t).modInverse(param.OrderSignma);
            BigInteger SN = param.B1.modPow(is_inv,param.Sigma).multiply(param.B2.modPow(it_inv,param.Sigma)).mod(param.Sigma);
            System.out.println(SN);
        }
    }
}
