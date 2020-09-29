package com.gud.job;

import org.pcap4j.util.MacAddress;

import java.net.*;
import java.util.Stack;

public class Test {
    public static void main(String[] args) throws UnknownHostException {
        Inet4Address localHost = (Inet4Address) InetAddress.getLocalHost();
        System.out.println(localHost);
        InetAddress srcAddr = PcapUtils.getLocalHostIp();
        System.out.println(PcapUtils.getMACAddress(srcAddr));


        Stack<Integer> stack=new Stack<>();

    }
}
