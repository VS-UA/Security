package com.github.detiuaveiro.auth.auth.gui;

import com.github.detiuaveiro.auth.auth.AuthApplication;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.sql.SQLException;
import java.util.List;

public class UserInterface {
    private JFrame mainFrame;
    private JLabel headerLabel;
    private JLabel statusLabel;
    private JLabel explainLabel;
    private JPanel controlPanel;
    private JFrame subFrame;

    private JTextField fileName;
    private JTextField fileDecryptor;
    private JTextField entryDecryptor;
    private TextField tf;

    private JFrame mainRFrame;
    private JLabel headerRLabel;
    private JPanel controlRPanel;

    private String sessionID;

    public static void main(String[] args) {
        new UserInterface().prepareGUI();
    }


    public void prepareGUI() {
        mainFrame = new JFrame("Auth Interface");
        mainFrame.setSize(600, 500);
        mainFrame.setLayout(new GridLayout(3, 1));

        headerLabel = new JLabel("", JLabel.CENTER);
        statusLabel = new JLabel("", JLabel.CENTER);
        statusLabel.setSize(350, 100);
        explainLabel = new JLabel("", JLabel.CENTER);

        mainFrame.addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent windowEvent) {
                System.exit(0);
            }
        });
        controlPanel = new JPanel();
        controlPanel.setLayout(new FlowLayout());

//        mainFrame.add()

        mainFrame.add(headerLabel);
        mainFrame.add(controlPanel);

        final Box b = Box.createVerticalBox();
        mainFrame.add(b);
        b.add(statusLabel);
        b.add(explainLabel);

        tf = new TextField("When the session id is given, it will be here");
        tf.setEditable(false);

        b.add(tf);

        mainFrame.setVisible(true);
        showGUI();
    }

    public void setStatus(String s, boolean isError, String... sessionID) {
        if (!isError) {
            JOptionPane.showMessageDialog(null, s, "Status ", JOptionPane.INFORMATION_MESSAGE);
            tf.setText(sessionID[0]);
        } else {
            JOptionPane.showMessageDialog(null, s, "Status ", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void showGUI() {
        headerLabel.setText("Interface");
        statusLabel.setText("Fill the fields with valid information and press login to continue the process");
        explainLabel.setText("Before proceeding, you need to decrypt the database. Only then the site can authenticate you");

        JPanel p1 = new JPanel(new GridLayout(6, 2));

        JLabel jlfile = new JLabel("Path: ");
        this.fileName = new JTextField(20);
        p1.add(jlfile);
        p1.add(fileName);
        JLabel jlpasswordF = new JLabel("Password decrypt file: ");
        JLabel jlpasswordC = new JLabel("Password decrypt columns: ");
        this.fileDecryptor = new JPasswordField(20);
        this.entryDecryptor = new JPasswordField(20);
        p1.add(jlpasswordF);
        p1.add(fileDecryptor);
        p1.add(jlpasswordC);
        p1.add(entryDecryptor);
        controlPanel.add(p1);

        JButton submitButton = new JButton("Login");

        submitButton.setActionCommand("Login");
        submitButton.addActionListener(new ButtonClickListener());
        controlPanel.add(submitButton);
        mainFrame.setVisible(true);
    }


    private class ButtonClickListener implements ActionListener {
        public void actionPerformed(ActionEvent e) {
//            showResults(new String[]{"a", "b", "c"});

            String command = e.getActionCommand();

            if (command.equals("Login")) {
                statusLabel.setText("Waiting for a website request, please access the login page or reload it");

                if (fileDecryptor != null && !fileDecryptor.getText().equals("") &&
                        entryDecryptor != null && !entryDecryptor.getText().equals("") &&
                        fileName != null && !fileName.getText().equals("")) {
                    if (isValidFilePath(fileName.getText())) {
//                        showResults(new String[]{"a", "b", "c"});
//                    	AuthApplication.processLogin(fileName.getText(), fileDecryptor.getText(), entryDecryptor.getText());
                        try {
                            AuthApplication.setup(fileName.getText(), fileDecryptor.getText(), entryDecryptor.getText());
                        } catch (IllegalBlockSizeException | IOException | BadPaddingException | InvalidKeyException ex) {
                            ex.printStackTrace();
                        }
                    } else {
                        statusLabel.setText("Fill the fields with valid information and press login to continue the process");
                        JOptionPane.showMessageDialog(null, "Input not Valid", "Status ", JOptionPane.ERROR_MESSAGE);
                    }
                } else {
                    statusLabel.setText("Fill the fields with valid information and press login to continue the process");
                    JOptionPane.showMessageDialog(null, "Input not Valid", "Status ", JOptionPane.ERROR_MESSAGE);
                }
            } else {
                System.exit(0);
            }
        }
    }

    public static boolean isValidFilePath(String path) {
        File f = new File(path);

        return f.exists() && !f.isDirectory();
    }

    private void prepareResults() {
        mainRFrame = new JFrame("Show Results");
        mainRFrame.setSize(400, 400);
        mainRFrame.setLayout(new GridLayout(3, 1));

        mainRFrame.addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent windowEvent) {
                System.exit(0);
            }
        });
        headerRLabel = new JLabel("", JLabel.CENTER);
        JLabel statusRLabel = new JLabel("", JLabel.CENTER);
        statusRLabel.setSize(350, 100);

        controlRPanel = new JPanel();
        controlRPanel.setLayout(new FlowLayout());

        mainRFrame.add(headerRLabel);
        mainRFrame.add(controlRPanel);
        mainRFrame.add(statusRLabel);
        mainRFrame.setVisible(true);
    }

    public String showResults(String url) throws SQLException, IllegalBlockSizeException, IOException, BadPaddingException, InvalidKeyException {
        final List<String> user = AuthApplication.getInstance().getDbInterface().getUsers(url);

        prepareResults();
        headerRLabel.setText("Select the user with which you want to log in");
        final DefaultComboBoxModel<String> users = new DefaultComboBoxModel<>();

        for (String s : user)
            users.addElement(s);

        final JComboBox<String> usersCombo = new JComboBox<>(users);
        usersCombo.setSelectedIndex(0);

        JScrollPane UsersListScrollPane = new JScrollPane(usersCombo);
        JButton showButton = new JButton("Select");

        final StringSetter code = new StringSetter();

        showButton.addActionListener(e ->
                code.setS(AuthApplication.getInstance().getAuthenticator().initAuthenticator(
                        (String) usersCombo.getSelectedItem(), url)));
        controlRPanel.add(UsersListScrollPane);
        controlRPanel.add(showButton);
        mainRFrame.setVisible(true);

        sessionID = code.getS();
        return code.getS();
    }

    public String getSessionID() {
        return sessionID;
    }
}

class StringSetter {
    private String s;

    public String getS() {
        return s;
    }

    public void setS(String s) {
        this.s = s;
    }
}