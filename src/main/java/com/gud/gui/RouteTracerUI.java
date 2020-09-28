package com.gud.gui;

import com.gud.job.PcapUtils;
import com.gud.job.RouteTracer;
import com.intellij.uiDesigner.core.GridConstraints;
import com.intellij.uiDesigner.core.GridLayoutManager;
import org.pcap4j.core.PcapNetworkInterface;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.List;

public class RouteTracerUI {
    private JPanel routeTracerPanel;
    private JButton traceBtn;
    private JTextField targetTextField;
    private JTextArea detailsTextArea;
    private JScrollPane detailsScrollPanel;
    private JComboBox nifComboBox;

    Thread traceThread = null;
    RouteTracer routeTracer = new RouteTracer();

    private void init() {
        List<PcapNetworkInterface> allDevs = PcapUtils.getAllDevs();
        for (int i = 0; i < allDevs.size(); i++) {
            nifComboBox.addItem(allDevs.get(i).getName());
        }
    }

    public RouteTracerUI() {
        init();
        traceBtn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                routeTracer.close();
                detailsTextArea.setText("");

                routeTracer = new RouteTracer();
                String targetStr = targetTextField.getText();
                //往traceRouter中传入detailsTextArea；
                routeTracer.setNif((String) nifComboBox.getModel().getSelectedItem());

                traceThread = new Thread(() -> {
                    routeTracer.traceRoute(targetStr, detailsTextArea);
                });
                traceThread.start();
            }
        });
    }

    public static void main(String[] args) {
        JFrame frame = new JFrame("RouteTracer");
        frame.setContentPane(new RouteTracerUI().routeTracerPanel);
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
        routeTracerPanel = new JPanel();
        routeTracerPanel.setLayout(new GridLayoutManager(3, 2, new Insets(0, 0, 0, 0), -1, -1));
        traceBtn = new JButton();
        traceBtn.setText("trace");
        routeTracerPanel.add(traceBtn, new GridConstraints(1, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        targetTextField = new JTextField();
        routeTracerPanel.add(targetTextField, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        detailsScrollPanel = new JScrollPane();
        routeTracerPanel.add(detailsScrollPanel, new GridConstraints(2, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, null, new Dimension(400, 240), null, 0, false));
        detailsTextArea = new JTextArea();
        detailsScrollPanel.setViewportView(detailsTextArea);
        nifComboBox = new JComboBox();
        routeTracerPanel.add(nifComboBox, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return routeTracerPanel;
    }

}
