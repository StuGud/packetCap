package com.gud.gui;

import com.gud.job.Loop;
import com.gud.job.PcapUtils;
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

public class PcapUI {
    private JPanel pcapPanel;
    private JButton start;
    private JTable listTable;
    private JComboBox nifComboBox;
    private JComboBox pacComboBox;
    private JScrollPane jScrollPane1;
    private JScrollPane jScrollPane2;
    private JTextArea packetDetailsTextArea;
    private JTextField filterTextField;
    private JButton pauseBtn;

    public static DefaultTableModel tableModel4lt;

    private Loop loop;
    private Thread t;

    public JPanel getPcapPanel() {
        return pcapPanel;
    }

    public void setPcapPanel(JPanel pcapPanel) {
        this.pcapPanel = pcapPanel;
    }

    public PcapUI() {
        init();

        start.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                //获取用户选择的网卡信息、包信息；刷新数据包列表；清空右侧详情
                loop.clear();
                packetDetailsTextArea.setText("");
                tableModel4lt.setRowCount(1);

                loop.setNif((String) nifComboBox.getModel().getSelectedItem());
                loop.setPacketType((String) pacComboBox.getModel().getSelectedItem());
                loop.setFilter(filterTextField.getText());

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

                t.start();
                packetDetailsTextArea.setText("");
            }
        });
        listTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {

                int selectedRow = listTable.getSelectedRow();
                if (e.getClickCount() == 2) {
                    int value = (int) tableModel4lt.getValueAt(selectedRow, 0);
                    //显示packet详情
                    Packet packet = (Packet) loop.getPacketVector().get(value);
                    //
                    packetDetailsTextArea.setText(String.valueOf(packet));
                }
            }
        });
        pauseBtn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                loop.pause();
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

        List<PcapNetworkInterface> allDevs = PcapUtils.getAllDevs();
        for (int i = 0; i < allDevs.size(); i++) {
            nifComboBox.addItem(allDevs.get(i).getName());
        }

        //packetComboBox
        for (String packetType : loop.getPacketTypes()) {
            pacComboBox.addItem(packetType);
        }

        final String[] columnNames1 = {"NO", "Source", "Destination", "Protocol", "Length", "Info"};
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
        frame.setContentPane(new PcapUI().pcapPanel);
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
        pcapPanel = new JPanel();
        pcapPanel.setLayout(new GridLayoutManager(4, 3, new Insets(0, 0, 0, 0), -1, -1));
        nifComboBox = new JComboBox();
        pcapPanel.add(nifComboBox, new GridConstraints(0, 0, 1, 2, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        pacComboBox = new JComboBox();
        pcapPanel.add(pacComboBox, new GridConstraints(1, 0, 1, 2, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        jScrollPane1 = new JScrollPane();
        pcapPanel.add(jScrollPane1, new GridConstraints(3, 0, 1, 2, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        listTable = new JTable();
        listTable.setEnabled(true);
        listTable.putClientProperty("terminateEditOnFocusLost", Boolean.FALSE);
        jScrollPane1.setViewportView(listTable);
        jScrollPane2 = new JScrollPane();
        pcapPanel.add(jScrollPane2, new GridConstraints(3, 2, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, null, new Dimension(300, 400), null, 0, false));
        packetDetailsTextArea = new JTextArea();
        jScrollPane2.setViewportView(packetDetailsTextArea);
        filterTextField = new JTextField();
        filterTextField.setText("");
        pcapPanel.add(filterTextField, new GridConstraints(2, 0, 1, 2, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        start = new JButton();
        start.setText("开始");
        pcapPanel.add(start, new GridConstraints(0, 2, 2, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        pauseBtn = new JButton();
        pauseBtn.setText("暂停");
        pcapPanel.add(pauseBtn, new GridConstraints(2, 2, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return pcapPanel;
    }

}


