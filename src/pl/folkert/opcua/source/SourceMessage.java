/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package pl.folkert.opcua.source;

/**
 *
 * @author kfolkert
 */
public enum SourceMessage {

    GET;

    public static SourceMessage fromInt(int i) {
        if (i < 0 || i > values().length - 1) {
            return null;
        } else {
            return values()[i];
        }
    }
}
