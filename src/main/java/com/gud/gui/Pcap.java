package com.gud.gui;

import com.gud.job.Loop;
import com.intellij.uiDesigner.core.GridConstraints;
import com.intellij.uiDesigner.core.GridLayoutManager;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.Packet;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;
import java.util.concurrent.locks.LockSupport;

public class Pcap {
    private JPanel jPanel;
    private JButton start;
    private JTable listTable;
    private JTable detailTable;
    private JComboBox nifComboBox;
    private JComboBox pacComboBox;
    private JScrollPane jScrollPane1;
    private JScrollPane jScrollPane2;
    private JTextArea packetDetailsTextArea;

    public static DefaultTableModel tableModel4lt;

    private Loop loop;
    private Thread t;

    public Pcap() {
        init();

        start.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                //获取用户选择的网卡信息、包信息；刷新数据包列表；清空右侧详情
                //nifComboBox.getModel().getSelectedItem();
                loop.setNif((String) nifComboBox.getModel().getSelectedItem());
                loop.setPacketType((String) pacComboBox.getModel().getSelectedItem());
                System.out.println(t.getState());

                if (t.getState() == Thread.State.TERMINATED) {
                    t = new Thread() {
                        public void run() {
                            try {
                                loop.cap();
                            } catch (PcapNativeException pcapNativeException) {
                                pcapNativeException.printStackTrace();
                            } catch (NotOpenException notOpenException) {
                                notOpenException.printStackTrace();
                            }
                        }
                    };
                }

                if (t.getState() != Thread.State.RUNNABLE) {

                    t.start();
                    packetDetailsTextArea.setText("");
                    start.setText("停止");
                } else if (t.getState() == Thread.State.RUNNABLE) {
                    try {
                        loop.handle.breakLoop();
                    } catch (NotOpenException notOpenException) {
                        notOpenException.printStackTrace();
                    }
                    start.setText("开始");

                }

            }
        });
        listTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {

                int selectedRow = listTable.getSelectedRow();
                if (e.getClickCount() == 2) {
                    int value = (int) tableModel4lt.getValueAt(selectedRow, 0);
                    //显示packet详情
                    Packet packet = (Packet) loop.getPacketMap().get(value);
                    //
                    packetDetailsTextArea.setText(String.valueOf(packet));
                }
            }
        });
    }

    private void init() {

        loop = new Loop();
        t = new Thread() {
            public void run() {
                try {
                    loop.cap();
                } catch (PcapNativeException pcapNativeException) {
                    pcapNativeException.printStackTrace();
                } catch (NotOpenException notOpenException) {
                    notOpenException.printStackTrace();
                }
            }
        };

        List<PcapNetworkInterface> allDevs = loop.getAllDevs();
        for (int i = 0; i < allDevs.size(); i++) {
            nifComboBox.addItem(allDevs.get(i).getName());
        }

        //packetComboBox
        for (String packetType : loop.getPacketTypes()) {
            pacComboBox.addItem(packetType);
        }

        final String[] columnNames1 = {"NO", "Time", "Source", "Destination", "Protocol", "Length", "Info"};
        //String[][] data = {{"1", "2"}};
        tableModel4lt = new DefaultTableModel(null, columnNames1) {
            public boolean isCellEditable(int row, int column) {
                return false;
            }

            ;
        };
        listTable.setModel(tableModel4lt);

//        final String[] columnNames2 = {"type", "content"};
//        tableModel4dt = new DefaultTableModel(null, columnNames2);
//        detailTable.setModel(tableModel4dt);
    }

    public static void main(String[] args) {
        JFrame frame = new JFrame("Pcap");
        frame.setContentPane(new Pcap().jPanel);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.pack();
        frame.setVisible(true);

    }

    public DefaultTableModel getTableModel4lt() {
        return tableModel4lt;
    }

    public void setTableModel4lt(DefaultTableModel tableModel4lt) {
        this.tableModel4lt = tableModel4lt;
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
        jPanel.setLayout(new GridLayoutManager(3, 3, new Insets(0, 0, 0, 0), -1, -1));
        nifComboBox = new JComboBox();
        jPanel.add(nifComboBox, new GridConstraints(0, 0, 1, 2, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        start = new JButton();
        start.setText("开始");
        jPanel.add(start, new GridConstraints(0, 2, 2, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        pacComboBox = new JComboBox();
        jPanel.add(pacComboBox, new GridConstraints(1, 0, 1, 2, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        jScrollPane1 = new JScrollPane();
        jPanel.add(jScrollPane1, new GridConstraints(2, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        listTable = new JTable();
        listTable.setEnabled(true);
        listTable.putClientProperty("terminateEditOnFocusLost", Boolean.FALSE);
        jScrollPane1.setViewportView(listTable);
        jScrollPane2 = new JScrollPane();
        jPanel.add(jScrollPane2, new GridConstraints(2, 2, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        packetDetailsTextArea = new JTextArea();
        jScrollPane2.setViewportView(packetDetailsTextArea);
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return jPanel;
    }

}


