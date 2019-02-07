/*
 * output_statistics_ncurses.h
 *
 *  Created on: Feb 7, 2019
 *      Author: jjustman
 *
 *      hacks:
 *
 *
  FILE *f = fopen("/dev/tty", "r+");
  SCREEN *screen = newterm(NULL, f, f);
  set_term(screen);

  //this goes to stdout
  fprintf(stdout, "hello\n");
  //this goes to the console
  fprintf(stderr, "some error\n");
  //this goes to display
  mvprintw(0, 0, "hello ncurses");
  refresh();
  getch();
  endwin();

  return 0;
 */

#ifndef OUTPUT_STATISTICS_NCURSES_H_
#define OUTPUT_STATISTICS_NCURSES_H_


#if defined OUTPUT_STATISTICS && OUTPUT_STATISTICS == NCURSES
#define __BW_STATS_NCURSES true
#define __PKT_STATS_NCURSES true

#include <stdarg.h>
#include <ncurses.h>                    /* ncurses.h includes stdio.h */
//wmove(bw_window, 0, 0 __VA_ARGS__); //vwprintf(bw_window, __VA_ARGS__);
WINDOW* my_window;

WINDOW* bw_window_outline;
WINDOW* pkt_global_stats_window_outline;
WINDOW* pkt_flow_stats_window_outline;

WINDOW* bw_window_runtime;
WINDOW* bw_window_lifetime;

WINDOW* pkt_global_stats_window;
WINDOW* pkt_global_loss_window;

WINDOW* pkt_flow_stats_window;

#define __BW_STATS_I(...) wprintw(bw_window_runtime, __VA_ARGS__);wprintw(bw_window_runtime,"\n");
#define __BW_STATS_L(...) wprintw(bw_window_lifetime, __VA_ARGS__);wprintw(bw_window_lifetime,"\n");
//#define __BW_STATS(...) wprintw(bw_window, __VA_ARGS__);wprintw(bw_window,"\n");
#define __BW_STATS_BORDER(...)
#define __BW_STATS_REFRESH(...) touchwin(bw_window_outline);wrefresh(bw_window_runtime);wrefresh(bw_window_lifetime);
#define __BW_CLEAR() werase(bw_window_runtime); werase(bw_window_lifetime);
//wclear(bw_window)

#define __PS_STATS(...)
#define __PS_STATS_G(...) wprintw(pkt_global_stats_window, __VA_ARGS__);wprintw(pkt_global_stats_window,"\n");
#define __PS_STATS_F(...) wprintw(pkt_flow_stats_window, __VA_ARGS__);wprintw(pkt_flow_stats_window,"\n");
#define __PS_STATS_L(...) wprintw(pkt_global_loss_window, __VA_ARGS__);wprintw(pkt_global_loss_window,"\n");
#define __PS_REFRESH_L() wrefresh(pkt_global_loss_window);

#define __PS_WARN(...) wprintw(pkt_flow_stats_window, __VA_ARGS__);wprintw(pkt_flow_stats_window,"\n");
#define __PS_REFRESH() wrefresh(pkt_global_stats_window); wrefresh(pkt_flow_stats_window);
#define __PS_CLEAR() werase(pkt_global_stats_window); werase(pkt_flow_stats_window);
#endif



#endif /* OUTPUT_STATISTICS_NCURSES_H_ */
