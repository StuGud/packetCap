package com.gud.job;

import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.*;
import org.pcap4j.util.MacAddress;

import javax.swing.*;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

/**
 * 问题分析：
 */

/**
 * ICMP    type:8 code:0 => Echo请求
 */

//改 srcAddress以及desMac
public class RouteTracer {
    private PcapNetworkInterface nif;
    private PcapHandle handle4capture;
    private PcapHandle handle4send;
    private Inet4Address srcAddr = null;
    private volatile boolean isClosed=false;

    //网关 MAC    寝室： 20:6b:e7:64:13:9d   校园网：00:00:5e:00:01:01   手机：f2:18:98:6e:7d:64
    private MacAddress dstMacAddress = MacAddress.getByName("20:6b:e7:64:13:9d");
    private MacAddress srcMacAddress = null;
    //最多的跳数
    final int N = 30;
    long[] intervalTime = new long[N];

    private List<Long> startTime = new ArrayList<>();

    public void setDstMacAddress(String dstMacAddressStr) {
        this.dstMacAddress = MacAddress.getByName(dstMacAddressStr);
    }

    public RouteTracer() {
        srcAddr= (Inet4Address) PcapUtils.getLocalHostIp();
        srcMacAddress=MacAddress.getByName(PcapUtils.getMACAddress(srcAddr));
    }

    public void traceRoute(String targetAddress, JTextArea textArea) {
        isClosed=false;
        startTime.clear();
        if (nif == null) {
            return;
        }

        Inet4Address targetAddr = null;
        try {
            targetAddr = (Inet4Address) InetAddress.getByName(targetAddress);
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        System.out.println(srcAddr);

        //构造发送和接受的handler
        try {
            handle4capture = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
            handle4send = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
        } catch (PcapNativeException e) {
            e.printStackTrace();
            textArea.append("请打开网卡权限");
        }
        if(handle4capture==null||handle4send==null){
            return;
        }


        // 不同的 type 对应不同的 Builder, 用于控制 icmp 的内层
        IcmpV4EchoPacket.Builder icmpV4Echo = new IcmpV4EchoPacket.Builder();

        //指定ICMP为Echo请求
        final IcmpV4Type type = IcmpV4Type.ECHO;
        final IcmpV4Code code = IcmpV4Code.NO_CODE;
        // 生成 icmp 外层的 Builder, 然后传入内层的 Builder
        IcmpV4CommonPacket.Builder icmpV4b = new IcmpV4CommonPacket.Builder();
        icmpV4b
                .type(type)
                .code(code)
                .payloadBuilder(icmpV4Echo)
                .correctChecksumAtBuild(true);

        // 与上面同理, 生成 ipv4 的 Builder, 然后传入 icmp 的 Builder
        IpV4Packet.Builder ipv4b = new IpV4Packet.Builder();
        ipv4b
                .version(IpVersion.IPV4)
                .tos(IpV4Rfc791Tos.newInstance((byte) 0)) // Type of service, 区分服务
                .identification((short) 100) // 标识符
                .protocol(IpNumber.ICMPV4) // 协议
                .payloadBuilder(icmpV4b)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true);

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
                    if (packet.contains(IcmpV4CommonPacket.class) && packet.get(IpV4Packet.class).getHeader().getDstAddr().equals(finalSrcAddr)) {
                        //计算时延
                        if (packet.contains(IcmpV4TimeExceededPacket.class)) {
                            byte[] rawData = packet.getRawData();
                            System.out.print(rawData[67] + "  经过:" + packet.get(IpV4Packet.class).getHeader().getSrcAddr());
                            intervalTime[rawData[67] - 1] = System.currentTimeMillis() - startTime.get(rawData[67] - 1);
                            System.out.println("  时延：" + intervalTime[rawData[67] - 1] + "ms");

                            textArea.append(rawData[67] + "  经过:" + packet.get(IpV4Packet.class).getHeader().getSrcAddr() +
                                    "  时延：" + intervalTime[rawData[67] - 1] + "ms\n");
                        } else if (packet.contains(IcmpV4EchoReplyPacket.class)) {
                            byte[] rawData = packet.getRawData();
                            System.out.print(rawData[39] + "  到达终点:" + packet.get(IpV4Packet.class).getHeader().getSrcAddr());
                            intervalTime[rawData[39] - 1] = System.currentTimeMillis() - startTime.get(rawData[39] - 1);
                            System.out.println("  时延：" + intervalTime[rawData[39] - 1] + "ms");

                            textArea.append(rawData[39] + "  到达终点:" + packet.get(IpV4Packet.class).getHeader().getSrcAddr() +
                                    "  时延：" + intervalTime[rawData[39] - 1] + "ms\n");
                        } else if (packet.contains(IcmpV4DestinationUnreachablePacket.class)){
                            System.out.println("目的地不可达");
                            textArea.append("目的地不可达");
                        }
                    }
                };

        Thread loopThread = new Thread(() -> {
            while (true) {
                try {
                    handle4capture.loop(-1, listener);
                } catch (PcapNativeException e) {
                    e.printStackTrace();
                    textArea.append("请打开网卡权限");
                } catch (InterruptedException e) {
                    break;
                } catch (NotOpenException e) {
                    break;
                }
            }
        });
        loopThread.start();

        //发送N个ICMP包
        for (int i = 1; i <= N&&!isClosed; i++) {
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            icmpV4Echo.identifier((short) i);
            icmpV4b.payloadBuilder(icmpV4Echo);
            ipv4b.ttl((byte) i).payloadBuilder(icmpV4b);
            eb.payloadBuilder(ipv4b);
            try {
                handle4send.sendPacket(eb.build());
            } catch (PcapNativeException e) {
                e.printStackTrace();
                textArea.append("请打开网卡权限");
            } catch (NotOpenException e) {
                e.printStackTrace();
            }
            startTime.add(System.currentTimeMillis());
        }
    }

    public void close(){
        isClosed=true;
        if(handle4capture!=null){
            try {
                handle4capture.breakLoop();
                handle4capture.close();
            } catch (NotOpenException e) {
                e.printStackTrace();
            }
        }
        if (handle4send!=null){
            handle4send.close();
        }
    }

    public static void main(String[] args) {
        RouteTracer routeTracer = new RouteTracer();
        routeTracer.setNif("en0");
        routeTracer.traceRoute("www.baidu.com", null);
    }


    public void setNif(String nif) {
        try {
            System.out.println("select: " + nif);
            this.nif = Pcaps.getDevByName(nif);
        } catch (PcapNativeException e) {
            System.out.println("获取特定网卡失败");
            e.printStackTrace();
        }
    }
}
