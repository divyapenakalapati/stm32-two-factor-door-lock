   #define STM32F4
   #define SSD1306_I2C_PORT        hi2c1
   #define SSD1306_I2C_ADDR        (0x3C << 1)
   #define SSD1306_INCLUDE_FONT_7x10
   #define SSD1306_HEIGHT 64
#include "stm32f4xx_hal.h"



#define SSD1306_USE_I2C
//#define SSD1306_USE_SPI

#define SSD1306_I2C_PORT   hi2c1
#define SSD1306_I2C_ADDR   (0x3C << 1)
