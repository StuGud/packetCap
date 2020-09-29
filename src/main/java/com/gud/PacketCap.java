package com.gud;

import com.gud.gui.APITestUI;
import com.gud.gui.ARPAttackUI;
import com.gud.gui.PcapUI;
import com.gud.gui.RouteTracerUI;

import javax.swing.*;
import java.awt.*;

public class PacketCap extends JFrame {
    private JPanel contentPane;
    JPanel panel;//主函数提供显示，不用看！
    JMenuBar mb;

    PacketCap(){
        //setBounds(100,100,200,200);
        setVisible(true);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        init();
    }

    public void init(){
        this.setBounds(50, 50, 850, 530);
        contentPane = new JPanel();
        //contentPane.setLayout(null);
        this.setContentPane(contentPane);

        panel=new PcapUI().getPcapPanel();
        contentPane.add(panel);
        //panel.setLayout(null);

        mb = new JMenuBar();
        this.setJMenuBar(mb);
        JMenu menu = new JMenu("功能");
        JMenuItem pcapMenuItem = new JMenuItem("抓包");
        pcapMenuItem.addActionListener(arg0 -> {
            // TODO Auto-generated method stub
            contentPane.remove(panel);
            panel=new PcapUI().getPcapPanel();
            contentPane.add(panel);
            setContentPane(contentPane);
        });
        JMenuItem apiTestMenuItem = new JMenuItem("API测试");
        apiTestMenuItem.addActionListener(arg0 -> {
            // TODO Auto-generated method stub
            contentPane.remove(panel);
            panel=new APITestUI().getApiTestPanel();
            contentPane.add(panel);
            setContentPane(contentPane);
        });
        JMenuItem arpAttackMenuItem = new JMenuItem("ARP攻击");
        arpAttackMenuItem.addActionListener(arg0 -> {
            // TODO Auto-generated method stub
            contentPane.remove(panel);
            panel=new ARPAttackUI().getArpAttackPanel();
            contentPane.add(panel);
            setContentPane(contentPane);
        });
        JMenuItem routeTracerMenuItem = new JMenuItem("tracert");
        routeTracerMenuItem.addActionListener(arg0 -> {
            // TODO Auto-generated method stub
            contentPane.remove(panel);
            panel=new RouteTracerUI().getRouteTracerPanel();
            contentPane.add(panel);
            setContentPane(contentPane);
        });
        menu.add(pcapMenuItem);
        menu.add(apiTestMenuItem);
        menu.add(arpAttackMenuItem);
        menu.add(routeTracerMenuItem);
        mb.add(menu);
        mb.setVisible(true);
    }

    public static void main(String[] args) {
        EventQueue.invokeLater(new Runnable() {
            public void run() {
                try {
                    PacketCap frame = new  PacketCap();
                    frame.setVisible(true);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
    }
}
