package com.clone.firstStep;

import java.math.BigInteger;
import java.util.Random;

public class generateNum {


    public static BigInteger generateNum(int length){
        BigInteger num = Parameter.bigTwo;
        Random  random = new Random();
        num=num.pow(length-1);
        BigInteger ad = new BigInteger(length-1,random);
        return num.add(ad);
    }
    public static BigInteger generateNum(int length,int rand){
        BigInteger num = Parameter.bigTwo;
        Random  random = new Random(rand);
        num=num.pow(length-1);
//        System.out.println(num.toString(2));
        BigInteger ad = new BigInteger(length-1,random);
        return num.add(ad);
    }
    public static BigInteger generatePrime(int length){
        Random random = new Random();
        BigInteger num  = BigInteger.probablePrime(length,random);
        while (num.bitLength() != length){
            num = BigInteger.probablePrime(length,random);
        }
        return num;
    }
    public static BigInteger generatePrime(int length,int rand){
        Random random = new Random(rand);
        BigInteger num  = BigInteger.probablePrime(length,random);
        while (num.bitLength() != length){
            num = BigInteger.probablePrime(length,random);
        }
        return num;
    }
}
