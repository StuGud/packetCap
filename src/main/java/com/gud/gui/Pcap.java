package com.gud.gui;

import com.gud.job.Loop;
import org.pcap4j.core.PcapNetworkInterface;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;

public class Pcap {
    private JPanel jPanel;
    private JButton start;
    private JTable listTable;
    private JTable detailTable;
    private JComboBox nifComboBox;
    private JComboBox pacComboBox;

    private Loop loop;

    public Pcap() {
        init();

        start.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                //获取用户选择的网卡信息、包信息；刷新数据包列表；清空右侧详情
                //nifComboBox.getModel().getSelectedItem();
                loop.setNif((String) nifComboBox.getModel().getSelectedItem());
                loop.setPacketType((String) pacComboBox.getModel().getSelectedItem());
                System.out.println("hello");
            }
        });
        listTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int selectedRow = listTable.getSelectedRow();
                    DefaultTableModel dtm = (DefaultTableModel) listTable.getModel();
                    String value = (String) dtm.getValueAt(selectedRow, 0);
                    //显示packet详情
                }
            }
        });
    }

    private void init() {
        loop = new Loop();

        List<PcapNetworkInterface> allDevs = loop.getAllDevs();
        for (int i = 0; i < allDevs.size(); i++) {
            nifComboBox.addItem(allDevs.get(i).getName());
        }

        //packetComboBox
        //填充支持的协议？
        for (String packetType : loop.getPacketTypes()) {
            pacComboBox.addItem(packetType);
        }
    }

    public static void main(String[] args) {
        JFrame frame = new JFrame("Pcap");
        frame.setContentPane(new Pcap().jPanel);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.pack();
        frame.setVisible(true);
    }

    {
// GUI initializer generated by IntelliJ IDEA GUI Designer
// >>> IMPORTANT!! <<<
// DO NOT EDIT OR ADD ANY CODE HERE!
        $$$setupUI$$$();
    }

    /**
     * Method generated by IntelliJ IDEA GUI Designer
     * >>> IMPORTANT!! <<<
     * DO NOT edit this method OR call it in your code!
     *
     * @noinspection ALL
     */
    private void $$$setupUI$$$() {
        jPanel = new JPanel();
        jPanel.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(3, 3, new Insets(0, 0, 0, 0), -1, -1));
        listTable = new JTable();
        listTable.setEnabled(false);
        jPanel.add(listTable, new com.intellij.uiDesigner.core.GridConstraints(2, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, null, new Dimension(150, 50), null, 0, false));
        detailTable = new JTable();
        detailTable.setEnabled(false);
        jPanel.add(detailTable, new com.intellij.uiDesigner.core.GridConstraints(2, 2, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, null, new Dimension(150, 50), null, 0, false));
        nifComboBox = new JComboBox();
        jPanel.add(nifComboBox, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 2, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        start = new JButton();
        start.setText("开始");
        jPanel.add(start, new com.intellij.uiDesigner.core.GridConstraints(0, 2, 2, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        pacComboBox = new JComboBox();
        jPanel.add(pacComboBox, new com.intellij.uiDesigner.core.GridConstraints(1, 0, 1, 2, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return jPanel;
    }

}
