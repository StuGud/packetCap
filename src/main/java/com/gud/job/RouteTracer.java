package com.gud.job;

import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.*;
import org.pcap4j.util.IcmpV4Helper;
import org.pcap4j.util.IpV4Helper;
import org.pcap4j.util.MacAddress;
import org.pcap4j.util.NifSelector;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * 问题分析：
 * Mac地址
 * sendPacket没发出去
 *
 */

/**
 * ICMP    type:8 code:0 => Echo请求
 */
public class RouteTracer {

    //网关 MAC    寝室： 20:6b:e7:64:13:9d   校园网：00:00:5e:00:01:01
    private static MacAddress dstMacAddress = MacAddress.getByName("20:6b:e7:64:13:9d");
    private static MacAddress srcMacAddress = MacAddress.getByName("a4:83:e7:88:35:6b");
    //最多的跳数
    final int N=30;

    private RouteTracer() {
    }

    public void traceRoute(String targetAddress) throws PcapNativeException, NotOpenException, InterruptedException {
        Inet4Address targetAddr=null;
        Inet4Address srcAddr = null;
        try {
             targetAddr = (Inet4Address) InetAddress.getByName(targetAddress);
             srcAddr = (Inet4Address) InetAddress.getLocalHost();
             srcAddr = (Inet4Address) InetAddress.getByName("192.168.1.106");
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        System.out.println(srcAddr);

        //指定ICMP为Echo请求
        final IcmpV4Type type = IcmpV4Type.ECHO;
        final IcmpV4Code code = IcmpV4Code.NO_CODE;


        //选择网卡
        PcapNetworkInterface nif;
        try {
            nif = new NifSelector().selectNetworkInterface();
        } catch (IOException e) {
            e.printStackTrace();
            return;
        }

        if (nif == null) {
            return;
        }

        System.out.println(nif.getName() + "(" + nif.getDescription() + ")");


        //构造发送和接受的handler
        final PcapHandle handle4capture = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
        final PcapHandle handle4send = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);

//        handle4capture.setFilter( // 只监听发往网关的数据包
//                "(ether dst "
//                        + MAC_ADDR
//                        + ") or (arp and ether dst "
//                        + Pcaps.toBpfString(MacAddress.ETHER_BROADCAST_ADDRESS)
//                        + ")",
//                BpfProgram.BpfCompileMode.OPTIMIZE);

        // 不同的 type 对应不同的 Builder, 用于控制 icmp 的内层
        final Packet.Builder icmpV4Echo = new IcmpV4EchoPacket.Builder();

        // 生成 icmp 外层的 Builder, 然后传入内层的 Builder
        IcmpV4CommonPacket.Builder icmpV4b = new IcmpV4CommonPacket.Builder();
        icmpV4b.type(type).code(code).payloadBuilder(icmpV4Echo).correctChecksumAtBuild(true);

        // 与上面同理, 生成 ipv4 的 Builder, 然后传入 icmp 的 Builder
        IpV4Packet.Builder ipv4b = new IpV4Packet.Builder();
        ipv4b
                .version(IpVersion.IPV4)
                .tos(IpV4Rfc791Tos.newInstance((byte) 0)) // Type of service, 区分服务
                .identification((short) 100) // 标识符
                .protocol(IpNumber.ICMPV4) // 协议
                .payloadBuilder(icmpV4b);

        // 与上面同理, 生成 Ethernet 的 Builder, 然后传入 IP 的 Builder
        EthernetPacket.Builder eb = new EthernetPacket.Builder();
        eb.type(EtherType.IPV4).payloadBuilder(ipv4b).paddingAtBuild(true); // 填充

        // 上面的过程只是简单的确定了数据包的结构, 数据包的内部详细还没有确定

        ipv4b.srcAddr(srcAddr);
        ipv4b.dstAddr(targetAddr);
        eb.srcAddr(srcMacAddress);
        eb.dstAddr(dstMacAddress);

        Inet4Address finalSrcAddr = srcAddr;
        final PacketListener listener =
                packet -> { // 回调逻辑 -> 确定数据包内部详细 -> 回复 icmp
                    // 如果收到的报文为 icmp 回送请求或回送回答报文
                    if (packet.contains(IcmpV4EchoReplyPacket.class)) {
                        if(packet.get(IpV4Packet.class).getHeader().getDstAddr()== finalSrcAddr){
                            System.out.println("ICMP=================");
                            System.out.println(packet);
                            //计算时延
                            System.out.println(packet.get(IpV4Packet.class).getHeader().getDstAddr());
                            System.out.println(packet.get(IpV4Packet.class).getHeader().getSrcAddr());
                            System.out.println(packet.get(EthernetPacket.class).getHeader().getDstAddr());
                            System.out.println(packet.get(EthernetPacket.class).getHeader().getSrcAddr());
                        }


                    }
                };

        ExecutorService executor = Executors.newSingleThreadExecutor();
        executor.execute(
                new Runnable() {
                    @Override
                    public void run() {
                        while (true) {
                            try {
                                handle4capture.loop(-1, listener);
                            } catch (PcapNativeException e) {
                                e.printStackTrace();
                            } catch (InterruptedException e) {
                                break;
                            } catch (NotOpenException e) {
                                break;
                            }
                        }
                    }
                });

        for (int i = 1; i <= N; i++) {
            Thread.sleep(1000);
            ipv4b.ttl((byte)i)
                    .correctChecksumAtBuild(true) // 计算校验和
                    .correctLengthAtBuild(true); // 计算长度;
            eb.payloadBuilder(ipv4b);
            handle4send.sendPacket(eb.build());
            handle4send.sendPacket(eb.build());
            handle4send.sendPacket(eb.build());
//            System.out.println(eb.build());
            System.out.println("已发送echo"+i);
        }



        block(); // 输入回车关闭程序
        handle4capture.breakLoop();

        handle4capture.close();
        handle4send.close();
        executor.shutdown();
    }

    public static void main(String[] args) throws PcapNativeException, NotOpenException, InterruptedException {
        new RouteTracer().traceRoute("192.168.1.108");
    }

    private static void block() {
        try {
            Thread.sleep(2000);
        } catch (InterruptedException e1) {
        }

        BufferedReader r = null;

        try { // 读入命令行输入, 即输入回车结束程序
            r = new BufferedReader(new InputStreamReader(System.in));
            System.out.println("** Hit Enter key to stop simulation **");
            r.readLine();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                if (r != null) {
                    r.close();
                }
            } catch (IOException e) {
            }
        }
    }
}
