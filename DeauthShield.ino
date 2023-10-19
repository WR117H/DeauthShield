/*      __  __                ____       __            __            
 *     / / / /___ __  ___  __/ __ \___  / /____  _____/ /_____  _____
 *    / /_/ / __ `/ |/_/ |/_/ / / / _ \/ __/ _ \/ ___/ __/ __ \/ ___/
 *   / __  / /_/ />  <_>  </ /_/ /  __/ /_/  __/ /__/ /_/ /_/ / /    
 *  /_/ /_/\__,_/_/|_/_/|_/_____/\___/\__/\___/\___/\__/\____/_/     
 * 
 *  A simple deauth + dissassociation attack detector written for the WiFi Nugget
 *  github.com/HakCat/HaxxDetector
 * 
 *  By Alex Lynd | alexlynd.com
 *  
 */

#include <ESP8266WiFi.h>       
#include <Adafruit_NeoPixel.h>
#include <Wire.h>
#include "SH1106Wire.h"
#include "OLEDDisplayUi.h"

#include "nuggs.h" // Nugget Face bitmap files

Adafruit_NeoPixel pixels {1, D8, NEO_GRB + NEO_KHZ800 }; // initialize 1 NeoPixel on D8

SH1106Wire display(0x3c, D2, D1); // initialize OLED on I2C pins
OLEDDisplayUi ui     ( &display );

extern "C" {
#include "user_interface.h"
}

const short channels[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}; // Max: US 11, EU 13, JAP 14

int ch_index { 0 };               
int packet_rate { 0 };            
int attack_counter { 0 };         
unsigned long update_time { 0 };  
unsigned long ch_time { 0 };

void sniffer(uint8_t *buf, uint16_t len) {
  if (!buf || len < 28) return;
  byte pkt_type = buf[12];
  
  if (pkt_type == 0xA0 || pkt_type == 0xC0) { // flag deauth & dissassociation frames
    ++packet_rate;
  }
}

void attack_started() {
  pixels.setPixelColor(0, pixels.Color(150, 0, 0)); pixels.show(); // red
  displayDeadNugg();
}

void attack_stopped() {
  pixels.setPixelColor(0, pixels.Color(0, 150, 0)); pixels.show(); // green
  displayAliveNugg();
}

void setup() {
  Serial.begin(115200);           // initialize serial communication
  pixels.begin(); pixels.clear(); // initialize NeoPixel
  ui.setTargetFPS(60); ui.init(); // initialize OLED screen

  // initalize WiFi card for scanning
  WiFi.disconnect();
  wifi_set_opmode(STATION_MODE);       
  wifi_set_promiscuous_rx_cb(sniffer);
  wifi_set_channel(1);        
  wifi_promiscuous_enable(true);       

  Serial.println("\ngithub.com/WR117H/DeauthDetector");
  Serial.println("A WiFi Nugget sketch by Wraith");

  display.clear();
  display.flipScreenVertically();
  pixels.setPixelColor(0, pixels.Color(0, 150, 0)); pixels.show();
  displayAliveNugg();

}

void loop() {
  unsigned long current_time = millis();
  if (current_time - update_time >= (sizeof(channels) * 100UL)) {
    update_time = current_time;
    if (packet_rate >= 1) {
      ++attack_counter;
    } else {
      if (attack_counter >= 1) {
        attack_stopped();
      }
      attack_counter = 0;
    }
    if (attack_counter == 1) {
      attack_started();
    }
    packet_rate = 0;
  }
  // Channel hopping
  if (ch_index < sizeof(channels) && current_time - ch_time >= 100) {
    ch_time = current_time; // Update time variable
    short ch = channels[ch_index];
    wifi_set_channel(ch);
    ch_index = (ch_index + 1) % sizeof(channels);
  }
}

void displayDeadNugg() {
  display.clear();
  display.setFont(DejaVu_Sans_Mono_10);
  display.drawString(0,17,"Detected");
  
  display.drawLine(0, 54, 128, 54);
  display.drawLine(0, 53, 127, 53);
  
  display.drawXbm(0, 0, alive_nugg_width, alive_nugg_height, dead_nugg);
  display.drawString(0,54,"Developed by WR117H");
  display.display();
}

void displayAliveNugg() {
  display.clear();
  display.setFont(DejaVu_Sans_Mono_10);
  display.drawString(0,17,"Detecting");
  display.drawLine(0, 54, 128, 54);
  display.drawLine(0, 53, 127, 53);
  display.drawXbm(0, 0, alive_nugg_width, alive_nugg_height, alive_nugg);
  display.drawString(0,54,"Developed by WR117H");
  display.display();
}
