package com.clone.firstStep;

import java.math.BigInteger;

public class Parameter {
    public static final double Epsilon = 1.5;
    public static final int k = 64;//bit-length of hash function
    public static final int Lamtha = 70;
    public static final int Gama = 210;
    public static final int Lp = 128;//bit-length of p and q
    public static final int Lsigma = 201;//bit-length of sigma
    public static final int L = 10;//bit-length authentication times
    public static final BigInteger bigZero = new BigInteger("0");
    public static final BigInteger bigOne = new BigInteger("1");
    public static final BigInteger bigTwo = new BigInteger("2");


    public  BigInteger K_at = new BigInteger("1021");//authentication times
    public BigInteger Sigma;// order of prime group G
    public BigInteger N;// p*q
    public BigInteger B;//generator of G
    public BigInteger B1;//generator of G
    public BigInteger B2;//generator of G
    public BigInteger Range1left;//-2^(lamtha-1)
    public BigInteger Range1right;//2^(lamtha-1)
    public BigInteger Range2left ;//-(sigma-1)/2
    public BigInteger Range2right ;//(sigma-1)/2
    public BigInteger Range3left;//0
    public BigInteger Range3right;//2^l-1
    public BigInteger Range4left ;//2^gama-2^lamtha
    public BigInteger Range4right ;//2^gama+2^lamtha
    public BigInteger Range5left;//-2^(k+lamtha)+2^(lamtha)
    public BigInteger Range5right;//(sigma-1)+2^(k+lamtha)-2^(lamtha)
    public BigInteger P_;
    public BigInteger Q_;
    private BigInteger P;
    private BigInteger Q;
    public BigInteger OrderN;
    public BigInteger OrderSignma;
    public QRn Qrn;
    public int EpisilonLamK;
    public int EpisilonLsigmaK;
    public int EpisilonLK;
    public int EpisilonGamaLamK;
    public int EpisilonDoulK;
    public int EpisilonLamLK;
    public int EpisilonDouLsigK;

//    public static void main(String[] args) {                  //生成sigma=2*p_+1
//        BigInteger p_ = generateNum.generatePrime(200);
//        BigInteger p = p_.multiply(new BigInteger("2")).add(new BigInteger("1"));
//        while (!p.isProbablePrime(100)){
//            p_ = generateNum.generatePrime(200);
//            p = p_.multiply(new BigInteger("2")).add(new BigInteger("1"));
//        }
//        System.out.println(p.bitLength());
//        System.out.println(p);
//    }
//public static void main(String[] args) {
//    BigInteger p_ = generateNum.generatePrime(128);
//    BigInteger q_ = generateNum.generatePrime(128);
//    System.out.println("p_ = "+p_);
//    System.out.println("q_ = "+q_);
//    BigInteger p = p_.multiply(new BigInteger("2")).add(new BigInteger("1"));
//    BigInteger q = q_.multiply(new BigInteger("2")).add(new BigInteger("1"));
//    BigInteger n = p.multiply(q);
//    System.out.println("p = "+p);
//    System.out.println("q = "+q);
//    System.out.println("n = "+n);
//}
//public static void main(String[] args) {
//    boolean flag =true;
//    BigInteger p = null;
//    BigInteger q = null;
//    BigInteger p_= null;
//    BigInteger q_= null;
//    int count = 0;
//    while (true){
//        p_ = generateNum.generatePrime(128,count);
//        q_ = generateNum.generatePrime(128,count+1);
//        p = p_.multiply(Parameter.bigTwo).add(Parameter.bigOne);
//        q = q_.multiply(Parameter.bigTwo).add(Parameter.bigOne);
//        if (p.isProbablePrime(100) && q.isProbablePrime(100)){
//            break;
//        }
//        count += 2;
//    }
//    System.out.println(p_);
//    System.out.println(q_);
//    System.out.println(p);
//    System.out.println(q);
//    System.out.println(p.multiply(q));
//}
//public static void main(String[] args) {
//    BigInteger rangeleft = bigTwo.pow(Gama).subtract(bigTwo.pow(Lamtha));
//    BigInteger rangeright = bigTwo.pow(Gama).add(bigTwo.pow(Lamtha));
//    Random rand = new Random();
//    BigInteger randy = new BigInteger(Lamtha+1,rand);
//    BigInteger y = rangeleft.add(randy);
//    while (!y.isProbablePrime(100)){
//        randy = new BigInteger(Lamtha+1,rand);
//        y = y = rangeleft.add(randy);
//    }
//    System.out.println(y);
//    BigInteger rangRleft = bigTwo.pow(Lamtha).subtract(bigTwo.pow(k+Lamtha));
//    System.out.println(rangRleft);
//    BigInteger rangRright = new BigInteger("1982234754968359277521993087644364479439612619123287113511222").subtract(rangRleft);
//    System.out.println(rangRright);
//}

    public Parameter() {
        generateN();
        generateQrn();
        generateSigma();
        generateRange1();
        generateRange2();
        generateRange3();
        generateRange4();
        generateRange5();
        generateBitnumber();
    }

    public void generateN () {
        boolean flag =true;
        while (true){
            P_ = generateNum.generatePrime(Lp);
            Q_ = generateNum.generatePrime(Lp);
            P = P_.multiply(Parameter.bigTwo).add(Parameter.bigOne);
            Q = Q_.multiply(Parameter.bigTwo).add(Parameter.bigOne);
            if (P.isProbablePrime(100) && Q.isProbablePrime(100)){
                break;
            }
        }
        N = P.multiply(Q);
        OrderN = P.subtract(bigOne).multiply(Q.subtract(bigOne));
    }
    public void generateQrn(){
        Qrn = new QRn();
        Qrn.A = generateNum.generateNum(100).modPow(bigTwo,N);
        Qrn.Ax = generateNum.generateNum(100).modPow(bigTwo,N);
        Qrn.As = generateNum.generateNum(100).modPow(bigTwo,N);
        Qrn.At = generateNum.generateNum(100).modPow(bigTwo,N);
        Qrn.Ai = generateNum.generateNum(100).modPow(bigTwo,N);
        Qrn.Ae = generateNum.generateNum(100).modPow(bigTwo,N);
        Qrn.Ad = generateNum.generateNum(100).modPow(bigTwo,N);
        Qrn.h = generateNum.generateNum(100).modPow(bigTwo,N);
    }

    public void generateSigma (){
        BigInteger p = generateNum.generatePrime(Lsigma-1);
        Sigma = p.multiply(bigTwo).add(bigOne);
        while (true){
            p = generateNum.generatePrime(Lsigma-1);
            Sigma = p.multiply(bigTwo).add(bigOne);
            if (Sigma.isProbablePrime(100)) break;
        }
        OrderSignma = Sigma.subtract(bigOne);
        B = generateNum.generateNum((Lsigma-1)/2);
        B1 = generateNum.generateNum((Lsigma-1)/2);
        B2 = generateNum.generateNum((Lsigma-1)/2);
    }
    public void generateRange1 (){
        Range1left =bigTwo.pow(Lamtha-1).negate();
        Range1right = bigTwo.pow(Lamtha-1);
    }
    public void generateRange2 (){
        Range2left = OrderSignma.divide(bigTwo).negate();//-(sigma-1)/2
        Range2right = OrderSignma.divide(bigTwo);//(sigma-1)/2
    }
    public void generateRange3 (){
        Range3left = bigZero;//0
        Range3right = bigTwo.pow(L).subtract(bigOne);//2^l-1
    }
    public void generateRange4 (){
        Range4left = bigTwo.pow(Gama).subtract(bigTwo.pow(Lamtha));
        Range4right = bigTwo.pow(Gama).add(bigTwo.pow(Lamtha));
    }
    public void generateRange5(){
//        public BigInteger Range5left;//-2^(k+lamtha)+2^(lamtha)
//        public BigInteger Range5right;//(sigma-1)+2^(k+lamtha)-2^(lamtha)
        Range5left = bigTwo.pow(Lamtha).subtract(bigTwo.pow(k+Lamtha));
        Range5right = bigTwo.pow(Lamtha+k).subtract(bigTwo.pow(Lamtha));
        Range5right = Range5right.add(OrderSignma);

    }
    public void generateBitnumber(){
        EpisilonLamK = (int) (Epsilon * (Lamtha + k));
        EpisilonLsigmaK = (int) (Epsilon * (Lsigma + k));
        EpisilonLK = (int) (Epsilon * (L + k));
        EpisilonGamaLamK = (int) (Epsilon * (Gama + Lamtha + k));
        EpisilonDoulK = (int) (Epsilon * (2*L + k));
        EpisilonLamLK = (int) (Epsilon * (L + Lamtha + k));
        EpisilonDouLsigK = (int) (Epsilon * (2*Lsigma + k));
    }
}
