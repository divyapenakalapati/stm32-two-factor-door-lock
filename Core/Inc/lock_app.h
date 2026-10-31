#ifndef LOCK_APP_H
#define LOCK_APP_H
void App_Init(void);   /* call once in main() after all MX_xxx_Init() */
void App_Loop(void);   /* call inside while(1) */
#endif
