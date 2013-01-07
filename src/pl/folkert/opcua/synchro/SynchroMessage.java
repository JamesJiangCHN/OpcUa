/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package pl.folkert.opcua.synchro;

/**
 *
 * @author kfolkert
 */
public enum SynchroMessage {

    SYNCHRO,
    PRIMARY,
    SECONDARY;

    public static SynchroMessage fromInt(int i) {
        if (i < 0 || i > values().length - 1) {
            return null;
        } else {
            return values()[i];
        }
    }
}
