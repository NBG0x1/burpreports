/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.burpunit.report;

/**
 * Enum for several issues prios.
 */
public enum IssuePriority {
    INFORMATION("Information", 1), LOW("Low", 2), MEDIUM("Medium", 3), HIGH("High", 4);
    private String issuePrioName;
    private int issuePrioValue;

    private IssuePriority(final String name, final int value) {
        this.issuePrioName = name;
        this.issuePrioValue = value;
    }

    public String getName() {
        return this.issuePrioName;
    }

    public int getValue() {
        return this.issuePrioValue;
    }

    @Override
    public String toString() {
        return "IssuePriority{" + "issuePrioName=" + issuePrioName + ", issuePrioValue=" + issuePrioValue + '}';
    }
    
}
