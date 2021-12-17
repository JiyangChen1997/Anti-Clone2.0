package com.clone.firstStep;


import java.math.BigInteger;
import java.util.Vector;

public class user {
    Parameter param;                                                        //publicParams
    public BigInteger secretKey;                                            //user secretKey
    public BigInteger publicKey;                                            //user publicKey
    private Vector<BigInteger> secParams = new Vector<>(9);     //user secretParams
    public BigInteger A;                                                    //A return from GM
    public BigInteger y;                                                    //y return from GM
    public zkproof21 zkProof21;                                             //messages sent in the first step of zkProof 2
    public BigInteger challenge;                                            //chanllenge from AP
    Vector<BigInteger> rand2 = null;                                        //random numbers in zkProof 2
    BigInteger A_;                                                          //A'
    BigInteger w_;                                                          //w'
    BigInteger rand;                                                        //r
    BigInteger rand_;                                                       //r'
    BigInteger T;                                                           //T
    BigInteger SN;                                                          //SN
    BigInteger D;                                                           //D
    BigInteger T1;                                                          //T1
    BigInteger T2;                                                          //T2
    BigInteger dA;                                                          //dA
    BigInteger dT;                                                          //dT
    BigInteger dT1;                                                         //dT1
    BigInteger dT2;                                                         //dT2
    BigInteger dT2_;                                                        //dT2'
    BigInteger dT3;                                                         //dT3
    BigInteger dT3_;                                                        //r13-r6-r7
    BigInteger dic;                                                         //dic
    BigInteger dic_;                                                        //r6 * ic - r11-K_at * r14
    BigInteger dSN1;                                                        //dSN1
    BigInteger dSN2;                                                        //dSN2
    BigInteger dD;                                                          //dD
    BigInteger R1;                                                          //R1
    BigInteger R2;                                                          //R2
    BigInteger ec;                                                          //ec
    BigInteger ic;                                                          //ic
    BigInteger ics;                                                         //(ic+s)
    BigInteger ict;                                                         //(ic+t)
    BigInteger ics_;                                                        //ics^(-1)
    BigInteger ict_;                                                        //ict^(-1)
    BigInteger w2;                                                          //w*
    BigInteger dA_;                                                         //
    BigInteger m;                                                           //e*e(-1) /K_at
    BigInteger e;                                                           //e
    BigInteger dic2_;
    BigInteger dic2;
    public user(Parameter parameter) {                                      //constructor of user
        this.param = parameter;                                             //get public params
        setSecretKey(100);                                                  //set secret key
        setPublicKey();                                                     //set public key
        setSecParams();                                                     //set secret params
    }
    public zkproof generateSPK (){                                          //generate zero-knowledge proof in joining protocol
        BigInteger s;
        Vector<BigInteger> r = new Vector<>(9);
        zkproof zkproof = new zkproof();
        BigInteger p1;
        BigInteger p2;
        BigInteger p3;
        BigInteger y1;
        BigInteger y2;
        BigInteger y3;
        r.add(generateNum.generateNum(200));                            //r0   random u
        BigInteger r1 = generateNum.generateNum(param.EpisilonLamK);                   //r1 random t1
        r.add(r1);
        r.add(generateNum.generateNum(param.EpisilonLamK));                            //r2 random x
        r.add(generateNum.generateNum(param.EpisilonLsigmaK));                            //r3 random s
        r.add(r1);                                                             //r4 random t1
        r.add(generateNum.generateNum(param.EpisilonLK));                            //r5 random i
        r.add(generateNum.generateNum(param.EpisilonLK));                            //r6 random e
        r.add(generateNum.generateNum(param.EpisilonLK));                            //r7 random d
        r.add(generateNum.generateNum(param.EpisilonLamK));                            //r8 random w



        BigInteger numc;
        String c="";
        MD5 md5 = new MD5();
        p1 = param.B.modPow(r.elementAt(0),param.Sigma);                //b^r0 mod sigma   random exp PKu
        p2 = param.B.modPow(r.elementAt(1),param.Sigma);                //b^r1 mod sigma   random exp J1
        p3 = param.Qrn.Ax.modPow(r.elementAt(2),param.N);
        p3 = p3.multiply(param.Qrn.As.modPow(r.elementAt(3),param.N)).mod(param.N);
        p3 = p3.multiply(param.Qrn.At.modPow(r.elementAt(4),param.N)).mod(param.N);
        p3 = p3.multiply(param.Qrn.Ai.modPow(r.elementAt(5),param.N)).mod(param.N);
        p3 = p3.multiply(param.Qrn.Ae.modPow(r.elementAt(6),param.N)).mod(param.N);
        p3 = p3.multiply(param.Qrn.Ad.modPow(r.elementAt(7),param.N)).mod(param.N);
        p3 = p3.multiply(param.Qrn.h.modPow(r.elementAt(8),param.N)).mod(param.N);
        BigInteger p4 = p3.multiply(param.Qrn.A).mod(param.N);                //    random exp J2
        c += param.B.toString()+param.Qrn.A.toString()+param.Qrn.Ax.toString()+param.Qrn.As.toString()+param.Qrn.At.toString()+
                param.Qrn.Ai.toString()+param.Qrn.Ae.toString()+param.Qrn.Ad.toString()+param.Qrn.h.toString();


        y1 = getPublicKey();                                                  // PKu
        y2 = param.B.modPow(secParams.elementAt(1),param.Sigma);        //J1
        y3 = param.Qrn.Ax.modPow(secParams.elementAt(2),param.N);
        y3 = y3.multiply(param.Qrn.As.modPow(secParams.elementAt(3),param.N)).mod(param.N);
        y3 = y3.multiply(param.Qrn.At.modPow(secParams.elementAt(4),param.N)).mod(param.N);
        y3 = y3.multiply(param.Qrn.Ai.modPow(secParams.elementAt(5),param.N)).mod(param.N);
        y3 = y3.multiply(param.Qrn.Ae.modPow(secParams.elementAt(6),param.N)).mod(param.N);
        y3 = y3.multiply(param.Qrn.Ad.modPow(secParams.elementAt(7),param.N)).mod(param.N);
        y3 = y3.multiply(param.Qrn.h.modPow(secParams.elementAt(8),param.N)).mod(param.N); //   J2/a
        c += y1.toString()+y2.toString()+y3.toString();
        c += p1.toString()+p2.toString()+p4.toString();
        c = md5.start(c);
        c = new BigInteger(c,16).toString(2).substring(0,param.k-1);
        c = new BigInteger(c,2).toString(2);
        numc = new BigInteger(c, 2);

        zkproof.c = numc.toString();
        zkproof.y.add(y1.toString());
        zkproof.y.add(y2.toString());
        zkproof.y.add(y3.toString());
        for (int i = 0; i < 9; i++) {
            s = r.elementAt(i).subtract(numc.multiply(secParams.elementAt(i)));
            zkproof.s.add(s.toString());
        }
        zkproof.m = "";
        return zkproof;
    }
    public zkproof21 generateSPK21 (){
        boolean flag = false;
        Vector<BigInteger> r = new Vector<>(9);
        r.add(generateNum.generateNum(param.EpisilonLamK));                                                                                 //r1   random (y-2^gama)
        r.add(generateNum.generateNum(param.EpisilonLamK));                                                                                 //r2   random x
        r.add(generateNum.generateNum(param.EpisilonLsigmaK));                                                                                 //r3   random s
        r.add(generateNum.generateNum(param.EpisilonLamK));                                                                                 //r4   random t
        r.add(generateNum.generateNum(param.EpisilonLK));                                                                                 //r5   random i
        r.add(generateNum.generateNum(param.EpisilonLK));                                                                                 //r6   random e
        r.add(generateNum.generateNum(param.EpisilonLK));                                                                                 //r7   random d
        r.add(generateNum.generateNum(param.EpisilonGamaLamK));                                                                                 //r8   random w'
        r.add(generateNum.generateNum(param.EpisilonLamK));                                                                                 //r9   random r
        r.add(generateNum.generateNum(param.EpisilonLamK));                                                                                 //r10   random r'
        r.add(generateNum.generateNum(param.EpisilonDoulK));                                                                                 //r11   random ie
        r.add(generateNum.generateNum(param.EpisilonLamLK));                                                                                 //r12   random r'e
        r.add(generateNum.generateNum(param.EpisilonLK));                                                                                 //r13   random ec
        r.add(generateNum.generateNum(param.EpisilonLK));                                                                                 //r14   random m
        r.add(generateNum.generateNum(param.EpisilonDouLsigK));                                                                                 //r15   random (ic+t)^(-1)(ic+s)
        r.add(generateNum.generateNum(param.EpisilonDouLsigK));                                                                                 //r16   random (ic+s)^(-1)(ic+t)
        w2 = generateNum.generateNum(Parameter.Lamtha);                                                                                    //w*
        rand = generateNum.generateNum(Parameter.Lamtha);                                                                                  //r
        A_ = A.multiply(param.Qrn.h.modPow(w2,param.N)).mod(param.N);                                                               //A'=A*(h^w*) mod n
        T = param.B1.modPow(secParams.elementAt(4),param.Sigma).multiply(param.B2.modPow(rand,param.Sigma)).mod(param.Sigma);//T = b1^t*b2^t mod sigma
        ec = secParams.elementAt(6).add(secParams.elementAt(7)).mod(param.K_at);                                        //ec = e+d mod K_at
        e = secParams.elementAt(6);
        BigInteger e_inv = e.modInverse(param.K_at);                                                                                //e^(-1)
        m = e.multiply(e_inv).divide(param.K_at);                                                                                   //(e*e^(-1)/K)
        ic = secParams.elementAt(5).add(e.modInverse(param.K_at)).mod(param.K_at);                                            //ic = i+(e)^(-1)
        while (ic.mod(Parameter.bigTwo).equals(Parameter.bigZero) ) {                                                               //confirm that ic is odd
            ic = ic.add(Parameter.bigOne).mod(param.K_at);
            flag = true;
        }
        ics = ic.add(secParams.elementAt(3));                                                                                 //ics = ic + s
        ics_ = ics.modInverse(param.OrderSignma);                                                                                   //ics_  = (ic+s)^(-1) mod ordersigma
        ict = ic.add(secParams.elementAt(4));//ict = ic + t
        ict_ = ict.modInverse(param.OrderSignma);                                                                                   //ict_  = (ic+t)^(-1) mod ordersigma
        SN = param.B1.modPow(ics_,param.Sigma).multiply(param.B2.modPow(ict_,param.Sigma)).mod(param.Sigma);                        //SN = b1^(ics_)*b2^(ict_) (mod sigma)
        w_ = secParams.elementAt(8).add(y.multiply(w2)).mod(param.OrderN);                                                    //w' = w + yw*
        D = param.Qrn.Ax.modPow(secParams.elementAt(2),param.N);                                                              //D = a*ax^(x)*as^(s)*at^(t)*ai^(i)*ae^(e)*ad^(d)*h^(w') mod n
        D = D.multiply(param.Qrn.As.modPow(secParams.elementAt(3),param.N)).mod(param.N);
        D = D.multiply(param.Qrn.At.modPow(secParams.elementAt(4),param.N)).mod(param.N);
        D = D.multiply(param.Qrn.Ai.modPow(ic,param.N)).mod(param.N);
        D = D.multiply(param.Qrn.Ae.modPow(ec,param.N)).mod(param.N);
        D = D.multiply(param.Qrn.Ad.modPow(secParams.elementAt(7),param.N)).mod(param.N);
        D = D.multiply(param.Qrn.h.modPow(w_,param.N)).mod(param.N);
        D = D.multiply(param.Qrn.A).mod(param.N); //    random exp J2
        rand_ = generateNum.generateNum(70);                                                                                 //r'
        T1 = param.B1.modPow(secParams.elementAt(5),param.Sigma).multiply(param.B2.modPow(rand_,param.Sigma)).mod(param.Sigma);//T1 = b1^(i)*b2^(r') mod sigma
        T2 = T1.modPow(secParams.elementAt(6),param.Sigma);                                                                    //T2 = T1^e mod sigma
        dA_ = param.Qrn.Ax.modPow(r.elementAt(1),param.N);                                                                     //dA_ = ax^(r2)*as^(r3)*at^(r4)*ai^(r5)*ae^(r6)*ad^(r7)*h^(r8) mod n
        dA_ = dA_.multiply(param.Qrn.As.modPow(r.elementAt(2),param.N)).mod(param.N);
        dA_ = dA_.multiply(param.Qrn.At.modPow(r.elementAt(3),param.N)).mod(param.N);
        dA_ = dA_.multiply(param.Qrn.Ai.modPow(r.elementAt(4),param.N)).mod(param.N);
        dA_ = dA_.multiply(param.Qrn.Ae.modPow(r.elementAt(5),param.N)).mod(param.N);
        dA_ = dA_.multiply(param.Qrn.Ad.modPow(r.elementAt(6),param.N)).mod(param.N);
        dA_ = dA_.multiply(param.Qrn.h.modPow(r.elementAt(7),param.N)).mod(param.N);
        dA_ = dA_.modInverse(param.N);
        dA = A_.modPow(r.elementAt(0),param.N).multiply(dA_).mod(param.N);                                                    //dA = (A')^(r1)/dA_ mod n
        dT = param.B1.modPow(r.elementAt(3),param.Sigma).multiply(param.B2.modPow(r.elementAt(8),param.Sigma)).mod(param.Sigma); // dT = b1^(r4)*b2^(r9) mod sigma
        dT1 = param.B1.modPow(r.elementAt(4),param.Sigma).multiply(param.B2.modPow(r.elementAt(9),param.Sigma)).mod(param.Sigma);// dT1 = b1^(r5)*b2^(r10) mod sigma
        dT2 = T1.modPow(r.elementAt(5),param.Sigma);                                                                                   // dT2 = T1^(r6) mod sigma
        dT2_ = param.B1.modPow(r.elementAt(10),param.Sigma).multiply(param.B2.modPow(r.elementAt(11),param.Sigma)).mod(param.Sigma); //dT2' = b1^(r11)*b2^(r12) mod sigma
        dT3_ = r.elementAt(12).subtract(r.elementAt(5).add(r.elementAt(6))).mod(param.K_at);                                   //dT3_ = r13-r6-r7
        dT3 = param.B.modPow(dT3_,param.Sigma);                                                                                                  //dT3 = b^(dT3_) mod sigma
        if (flag == false){
            dic_ = ic.multiply(r.elementAt(5)).subtract(r.elementAt(10).add(param.K_at.multiply(r.elementAt(13)))).mod(param.K_at); ; //dic_ = ic*r6 - r11-K_at * r14
        } else {
            dic_ = ic.multiply(r.elementAt(5)).subtract(r.elementAt(10).add(param.K_at.multiply(r.elementAt(13))).add(r.elementAt(5))).mod(param.K_at);
        }
        dic = param.Qrn.A.modPow(dic_,param.N); //dic = a^(dic_) mod n
        dSN1 = SN.modPow(r.elementAt(2),param.Sigma).multiply(param.B2.modPow(r.elementAt(14),param.Sigma).modInverse(param.Sigma)).mod(param.Sigma); //dSN1 = SN^(r3)*((b2)^(r15))^(-1) mod sigma
        dSN2 = SN.modPow(r.elementAt(3),param.Sigma).multiply(param.B1.modPow(r.elementAt(15),param.Sigma).modInverse(param.Sigma)).mod(param.Sigma); //dSN2 = SN^(r4)*((b1)^(r16))^(-1) mod sigma
        dD = param.Qrn.Ax.modPow(r.elementAt(1),param.N);                                                                                                   //dD = ax^(r2)*as^(r3)*at^(r4)*ae^(r13)*ad^(r7)*h^(r8) mod n
        dD = dD.multiply(param.Qrn.As.modPow(r.elementAt(2),param.N)).mod(param.N);
        dD = dD.multiply(param.Qrn.At.modPow(r.elementAt(3),param.N)).mod(param.N);
        dD = dD.multiply(param.Qrn.Ae.modPow(r.elementAt(12),param.N)).mod(param.N);
        dD = dD.multiply(param.Qrn.Ad.modPow(r.elementAt(6),param.N)).mod(param.N);
        dD = dD.multiply(param.Qrn.h.modPow(r.elementAt(7),param.N)).mod(param.N);
        zkproof21 zp21= new zkproof21();                                                       //messages need to be sent in the first step of the second proof
        zp21.A_ = A_.toString();
        zp21.T = T.toString();
        zp21.ic = ic.toString();
        zp21.SN = SN.toString();
        zp21.D = D.toString();
        zp21.T1 = T1.toString();
        zp21.T2 = T2.toString();
        zp21.d.addElement(dA.toString());
        zp21.d.addElement(dT.toString());
        zp21.d.addElement(dT1.toString());
        zp21.d.addElement(dT2.toString());
        zp21.d.addElement(dT2_.toString());
        zp21.d.addElement(dT3.toString());
        zp21.d.addElement(dic.toString());
        zp21.d.addElement(dSN1.toString());
        zp21.d.addElement(dSN2.toString());
        zp21.d.addElement(dD.toString());
        zp21.flag = flag;
        for (int i = 0; i < zp21.d.size(); i++) {
            System.out.println(zp21.d.elementAt(i));
        }
        zkProof21 = zp21;
        rand2 = r;
        return zp21;
    }
    public void receiveChallenge(BigInteger Cha){
        challenge = Cha;
    }       //receive challenge
    public zkproof22 generateSPK22 (){
        zkproof22 zpk22 = new zkproof22();
        String c = "";
        c += challenge.toString() + zkProof21.A_ + zkProof21.T + zkProof21.ic + zkProof21.SN + zkProof21.D + zkProof21.T1 +
                zkProof21.T2;
        for (int i = 0; i < zkProof21.d.size(); i++) {
            c += zkProof21.d.elementAt(i);
        }
        MD5 md5 = new MD5();
        c = md5.start(c);
        c = new BigInteger(c,16).toString(2).substring(0,param.k-1);
        c = new BigInteger(c,2).toString(2);
        BigInteger numc = new BigInteger(c, 2);
        BigInteger s;                                                                                                   //generate s
        s = rand2.elementAt(0).subtract(numc.multiply(y.subtract(new BigInteger("2").pow(210))));             //s1 = r1-c(y-2^gama)
        zpk22.s.add(s.toString());                                                                                      //
        s = rand2.elementAt(1).subtract(numc.multiply(secParams.elementAt(2)));                             //s2 = r2 - c*x
        zpk22.s.add(s.toString());                                                                                      //
        s = rand2.elementAt(2).subtract(numc.multiply(secParams.elementAt(3)));                             //s3 = r3 - c*s
        zpk22.s.add(s.toString());
        s = rand2.elementAt(3).subtract(numc.multiply(secParams.elementAt(4)));                             //s4 = r4 - c*t
        zpk22.s.add(s.toString());
        s = rand2.elementAt(4).subtract(numc.multiply(secParams.elementAt(5)));                             //s5 = r5 - c*i
        zpk22.s.add(s.toString());
        s = rand2.elementAt(5).subtract(numc.multiply(secParams.elementAt(6)));                             //s6 = r6 - c*e
        zpk22.s.add(s.toString());
        s = rand2.elementAt(6).subtract(numc.multiply(secParams.elementAt(7)));                             //s7 = r7 - c*d
        zpk22.s.add(s.toString());
        s = rand2.elementAt(7).subtract(numc.multiply(w_));                                                       //s8 = r8 - c*w'
        zpk22.s.add(s.toString());
        s = rand2.elementAt(8).subtract(numc.multiply(rand));                                                     //s9 = r9 - c*r
        zpk22.s.add(s.toString());
        s = rand2.elementAt(9).subtract(numc.multiply(rand_));                                                    //s10 = r10 - c*r'
        zpk22.s.add(s.toString());
        s = rand2.elementAt(10).subtract(numc.multiply(secParams.elementAt(5).multiply(secParams.elementAt(6)))); //s11 = r11 - c*i*e
        zpk22.s.add(s.toString());
        s = rand2.elementAt(11).subtract(numc.multiply(rand_.multiply(secParams.elementAt(6))));                        //s12 = r12 - c*r'*e
        zpk22.s.add(s.toString());
        s = rand2.elementAt(12).subtract(numc.multiply(ec));                                                                  //s13 = r13 - c*ec
        zpk22.s.add(s.toString());
        s = rand2.elementAt(13).subtract(numc.multiply(m));                                                                   //s14 = r14 - c*m
        zpk22.s.add(s.toString());
        s = rand2.elementAt(14).subtract(numc.multiply(ict_.multiply(ics)));                                                  //s15 = r15 - c*(ic+t)^(-1)*(ic+s)
        zpk22.s.add(s.toString());
        s = rand2.elementAt(15).subtract(numc.multiply(ics_.multiply(ict)));                                                  //s16 = r16 - c*(ic+s)^(-1)*(ic+t)
        zpk22.s.add(s.toString());
        System.out.println(secParams.elementAt(4));
        R1 = ics_.subtract(numc.multiply(secParams.elementAt(4)));                                                            //R1 = (ic+s)^(-1)-c*t
        zpk22.R1 = R1.toString();
        System.out.println(rand);
        R2 = ict_.subtract(numc.multiply(rand));                                                                                    //R2 = (ic+t)^(-1)-c*r
        zpk22.R2 = R2.toString();
        zpk22.c = numc.toString();
        return zpk22;
    }

    public void setSecretKey(int length) {
        this.secretKey = generateNum.generateNum(length,1);           //generate a random number whose bit-length is "length" as user's secret key
    }
    public void setPublicKey() {
        this.publicKey = param.B.modPow(this.secretKey,param.Sigma);       //user's public key = b^(seckey) mod(sigma)
    }
    public BigInteger getPublicKey() {
        return publicKey;
    }                 //get user's public key

    public BigInteger getSecretKey() {
        return secretKey;
    }                 //get user's secret key

    public void setSecParams() {
        secParams.add(this.getSecretKey());                                // secparams0    secretky
        BigInteger t1 = generateNum.generateNum(Parameter.Lamtha);                //  secparams1    t1
        if (t1.mod(Parameter.bigTwo).equals(Parameter.bigZero)){           // confirm that t1 is odd
            t1 = t1.add(Parameter.bigOne);
        }
        secParams.add(t1);
        secParams.add(generateNum.generateNum(Parameter.Lamtha));                 //  secparams2     x
        BigInteger s = generateNum.generateNum(Parameter.Lsigma);
        if (s.mod(Parameter.bigTwo).equals(Parameter.bigOne)){             // confirm that s is even
            s = s.add(Parameter.bigOne);
        }
        secParams.add(s);                                                 //   secparams3     s
        secParams.add(t1);                                                //   secparams4     t
        secParams.add(generateNum.generateNum(Parameter.L));                //    secparams5     i
        secParams.add(generateNum.generateNum(Parameter.L));                //    secparams6     e
        secParams.add(generateNum.generateNum(Parameter.L));                //    secparams7     d
        secParams.add(generateNum.generateNum(Parameter.Lamtha));                //    secparams8     w
    }
    public boolean verifyt2(BigInteger t2){                               //verify t2 received from GM
        if (t2.bitLength() == param.Lamtha) {
            return true;
        } else {
            return false;
        }
    }
    public boolean verifyY(BigInteger y){                                 //verify y received from GM
        if (y.compareTo(param.Range4left)==1 && y.compareTo(param.Range4right)==-1){
            return true;
        } else {
            return false;
        }
    }
    public boolean verifyA(BigInteger Aa,BigInteger t2,BigInteger y){                                   //verify A
        BigInteger p = param.Qrn.Ax.modPow(secParams.elementAt(2),param.N);
        p = p.multiply(param.Qrn.As.modPow(secParams.elementAt(3),param.N)).mod(param.N);
        p = p.multiply(param.Qrn.At.modPow(secParams.elementAt(4),param.N)).mod(param.N);
        p = p.multiply(param.Qrn.Ai.modPow(secParams.elementAt(5),param.N)).mod(param.N);
        p = p.multiply(param.Qrn.Ae.modPow(secParams.elementAt(6),param.N)).mod(param.N);
        p = p.multiply(param.Qrn.Ad.modPow(secParams.elementAt(7),param.N)).mod(param.N);
        p = p.multiply(param.Qrn.h.modPow(secParams.elementAt(8),param.N)).mod(param.N);
        p = p.multiply(param.Qrn.A).mod(param.N);
        p = p.multiply(param.Qrn.At.modPow(t2,param.N)).mod(param.N);
        Aa = Aa.modPow(y,param.N);                                                                      //A^y

        return Aa.equals(p);
    }
    public boolean verifyAD(BigInteger A,BigInteger y){                                                 //verify AD
        BigInteger p = param.Qrn.Ax.modPow(secParams.elementAt(2),param.N);
        p = p.multiply(param.Qrn.As.modPow(secParams.elementAt(3),param.N)).mod(param.N);
        p = p.multiply(param.Qrn.At.modPow(secParams.elementAt(4),param.N)).mod(param.N);
        p = p.multiply(param.Qrn.Ai.modPow(ic,param.N)).mod(param.N);
        p = p.multiply(param.Qrn.Ae.modPow(ec,param.N)).mod(param.N);
        p = p.multiply(param.Qrn.Ad.modPow(secParams.elementAt(7),param.N)).mod(param.N);
        p = p.multiply(param.Qrn.h.modPow(w_,param.N)).mod(param.N); //   J2/a
        p = p.multiply(param.Qrn.A).mod(param.N);
        A = A.modPow(y,param.N);                                                                        //AD^y'
        return A.equals(p);
    }
    public boolean verifyRe(Return11 re){                                                               // verify returned result from GM in joining
        if (!verifyt2(re.t2)){
            System.out.println("t2  false");
            return false;
        }
        if (!verifyY(re.y)){
            System.out.println("y  false");
            return false;
        }
        if (!verifyA(re.A,re.t2,re.y)){
            System.out.println("A  false");
            return false;
        }
        return true;
    }
    public boolean verifyRe2(Return2 re){                                                               // verify returned result from AP in authentication
        if (!verifyY(re.y_)){
            System.out.println("y  false");
            return false;
        }
        if (!verifyAD(re.AD,re.y_)){
            System.out.println("A  false");
            return false;
        }
        return true;
    }
    public void setT(BigInteger t2){// set t = t1 + t2
        BigInteger t = secParams.elementAt(4).add(t2);
        secParams.setElementAt(t,4);
    }
    public void generateAllSN(){                                                                        // generate all user's SN when user is dishonest
        BigInteger s = secParams.elementAt(3);
        BigInteger t = secParams.elementAt(4);
        for (int i = 1; i < 1021; i = i+2) {
            BigInteger bigi = BigInteger.valueOf(i);
            BigInteger is_inv = bigi.add(s).modInverse(param.OrderSignma);
            BigInteger it_inv = bigi.add(t).modInverse(param.OrderSignma);
            BigInteger SN = param.B1.modPow(is_inv,param.Sigma).multiply(param.B2.modPow(it_inv,param.Sigma)).mod(param.Sigma);
            System.out.println(SN);
        }
    }
}

