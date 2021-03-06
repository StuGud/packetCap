package com.gud.gui;

import com.gud.job.Loop;
import com.gud.job.PcapUtils;
import com.gud.job.SendArpRequest;
import com.intellij.uiDesigner.core.GridConstraints;
import com.intellij.uiDesigner.core.GridLayoutManager;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.List;

public class ARPAttackUI {
    private JPanel arpAttackPanel;
    private JComboBox nifCB;
    private JTextField destIPTF;
    private JTextField destPortTF;
    private JTextField srcIPTF;
    private JTextField srcPortTF;
    private JButton startBtn;
    private JTextArea destIPTextArea;
    private JTextArea destMACTextArea;
    private JTextArea srcIPTextArea;
    private JTextArea srcMACTextArea;
    private JTextArea rateMinTextArea;
    private JTextField rateTF;
    private JPanel destIPPanel;
    private JPanel destPortPanel;
    private JPanel ratePanel;
    private JPanel srcIPPanel;
    private JPanel srcPortPanel;

    public JPanel getArpAttackPanel() {
        return arpAttackPanel;
    }

    public ARPAttackUI() {
        init();

        startBtn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String nifStr = (String) nifCB.getModel().getSelectedItem();
                String srcIP = srcIPTF.getText();
                String srcMAC = srcPortTF.getText();
                String destIP = destIPTF.getText();
                String destMAC = destPortTF.getText();
                int rate = Integer.parseInt(rateTF.getText());
                int interval = 60 / rate;

                try {
                    SendArpRequest.SendArpAttack(nifStr, srcIP, srcMAC, destIP, destMAC, rate);
                } catch (PcapNativeException pcapNativeException) {
                    pcapNativeException.printStackTrace();
                } catch (NotOpenException notOpenException) {
                    notOpenException.printStackTrace();
                }

                //ARPAttack
            }
        });
    }

    private void init() {
        //nif
        Loop loop = new Loop();
        List<PcapNetworkInterface> allDevs = PcapUtils.getAllDevs();
        for (int i = 0; i < allDevs.size(); i++) {
            nifCB.addItem(allDevs.get(i).getName());
        }
    }

    public static void main(String[] args) {
        JFrame frame = new JFrame("ARPAttack");
        frame.setContentPane(new ARPAttackUI().arpAttackPanel);
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
        arpAttackPanel = new JPanel();
        arpAttackPanel.setLayout(new GridLayoutManager(3, 3, new Insets(0, 0, 0, 0), -1, -1));
        nifCB = new JComboBox();
        arpAttackPanel.add(nifCB, new GridConstraints(0, 0, 1, 2, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        destIPPanel = new JPanel();
        destIPPanel.setLayout(new GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        arpAttackPanel.add(destIPPanel, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_NORTHWEST, GridConstraints.FILL_NONE, 1, 1, null, null, null, 0, false));
        destIPTextArea = new JTextArea();
        destIPTextArea.setEditable(false);
        destIPTextArea.setEnabled(false);
        destIPTextArea.setText("destIP");
        destIPPanel.add(destIPTextArea, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(64, 16), null, 0, false));
        destIPTF = new JTextField();
        destIPPanel.add(destIPTF, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        destPortPanel = new JPanel();
        destPortPanel.setLayout(new GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        arpAttackPanel.add(destPortPanel, new GridConstraints(1, 1, 1, 1, GridConstraints.ANCHOR_NORTHWEST, GridConstraints.FILL_NONE, 1, 1, null, null, null, 0, false));
        destMACTextArea = new JTextArea();
        destMACTextArea.setEditable(false);
        destMACTextArea.setEnabled(false);
        destMACTextArea.setText("destMAC");
        destPortPanel.add(destMACTextArea, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(64, 16), null, 0, false));
        destPortTF = new JTextField();
        destPortPanel.add(destPortTF, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        srcIPPanel = new JPanel();
        srcIPPanel.setLayout(new GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        arpAttackPanel.add(srcIPPanel, new GridConstraints(2, 0, 1, 1, GridConstraints.ANCHOR_NORTHWEST, GridConstraints.FILL_NONE, 1, 1, null, null, null, 0, false));
        srcIPTextArea = new JTextArea();
        srcIPTextArea.setEditable(false);
        srcIPTextArea.setEnabled(false);
        srcIPTextArea.setText("srcIP");
        srcIPPanel.add(srcIPTextArea, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(64, 16), null, 0, false));
        srcIPTF = new JTextField();
        srcIPPanel.add(srcIPTF, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        srcPortPanel = new JPanel();
        srcPortPanel.setLayout(new GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        arpAttackPanel.add(srcPortPanel, new GridConstraints(2, 1, 1, 1, GridConstraints.ANCHOR_NORTHWEST, GridConstraints.FILL_NONE, 1, 1, null, null, null, 0, false));
        srcMACTextArea = new JTextArea();
        srcMACTextArea.setEditable(false);
        srcMACTextArea.setEnabled(false);
        srcMACTextArea.setText("srcMAC");
        srcPortPanel.add(srcMACTextArea, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(64, 16), null, 0, false));
        srcPortTF = new JTextField();
        srcPortTF.setText("");
        srcPortPanel.add(srcPortTF, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        ratePanel = new JPanel();
        ratePanel.setLayout(new GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        arpAttackPanel.add(ratePanel, new GridConstraints(1, 2, 1, 1, GridConstraints.ANCHOR_NORTHWEST, GridConstraints.FILL_NONE, 1, 1, null, null, null, 0, false));
        rateMinTextArea = new JTextArea();
        rateMinTextArea.setEditable(false);
        rateMinTextArea.setEnabled(false);
        rateMinTextArea.setText("rate/min");
        ratePanel.add(rateMinTextArea, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(80, 16), null, 0, false));
        rateTF = new JTextField();
        ratePanel.add(rateTF, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        startBtn = new JButton();
        startBtn.setText("attack");
        arpAttackPanel.add(startBtn, new GridConstraints(2, 2, 1, 1, GridConstraints.ANCHOR_NORTH, GridConstraints.FILL_NONE, 1, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return arpAttackPanel;
    }

}
