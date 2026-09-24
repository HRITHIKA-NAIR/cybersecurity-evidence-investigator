"""Generate precise, labelled layout diagrams for the separate wireframe document."""
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont
import textwrap
ROOT=Path(__file__).resolve().parent
OUT=ROOT/'assets';OUT.mkdir(exist_ok=True)
FONT='/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'
BOLD='/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf'

def canvas(title):
 im=Image.new('RGB',(1500,940),'white');d=ImageDraw.Draw(im)
 d.text((35,22),title,font=ImageFont.truetype(BOLD,34),fill='#1c2d29')
 return im,d

def box(d,x,y,w,h,title,body='',fill='#f3f5f4',size=22):
 d.rounded_rectangle((x,y,x+w,y+h),radius=12,fill=fill,outline='#aab7b1',width=2)
 d.text((x+18,y+16),title,font=ImageFont.truetype(BOLD,size),fill='#1c2d29')
 if body:
  wrapped='\n'.join(textwrap.fill(line,width=max(12,int((w-36)/(size*.53)))) for line in body.split('\n'))
  d.multiline_text((x+18,y+55),wrapped,font=ImageFont.truetype(FONT,size-2),fill='#40564b',spacing=7)

def shell(d,title):
 box(d,35,85,260,810,'EVIDENCE','Overview\n\nMy investigations\n\nINVESTIGATE\nLinks and websites\nEmails\nFiles and QR codes\nTexts and messages\n\nAlready affected?\nRecovery guidance',fill='#e4ebe7')
 box(d,320,85,1140,82,'Workspace / '+title,'',fill='#fff')
 d.text((1080,115),'Theme     Account',font=ImageFont.truetype(FONT,22),fill='#40564b')

im,d=canvas('01  Desktop overview and category selection');shell(d,'Overview')
box(d,320,190,1140,100,'A little clarity. A safer next step.','Understand suspicious content, evidence and recovery.')
box(d,320,315,1140,215,'Product introduction','What the investigator can do and where its limits are.\n[ Check something suspicious ]    Shield illustration',fill='#e8f1e8',size=26)
for x,t,b in [(320,'Links','Public URLs'),(612,'Emails','Text or .eml'),(904,'Files and QR','Upload one file'),(1196,'Messages','Paste text')]:box(d,x,560,264,170,t,b)
box(d,320,755,1140,140,'Explain the next steps','Bring evidence   >   Understand signals   >   Choose an action\nFooter: privacy, terms, deletion, acceptable use, copyright')
im.save(OUT/'wireframe-overview.png')

im,d=canvas('02  Focused investigation and mobile navigation');shell(d,'Investigation')
box(d,320,190,740,100,'Selected category','Use a clear, relevant evidence label.')
box(d,320,315,740,300,'Evidence form','[ Label + text field OR one file picker ]\n[ Supported file types when relevant ]\n[ Processing acknowledgement ]\nInline validation beside the input',size=24)
box(d,320,640,740,94,'[ Investigate evidence ]','')
box(d,320,760,740,135,'Preparation and recovery','Remove secrets. Keep the original safely.\nAlready affected? Open recovery guidance.')
box(d,1090,190,370,705,'Mobile at 390px','Brand          Menu\nTheme       Account\n\nPage heading\n\nEvidence form\n\nValidation\n\nPrimary action\n\nPreparation\n\nRecovery link\n\nFooter',fill='#fff')
im.save(OUT/'wireframe-investigation.png')

im,d=canvas('03  Results and progressive detail');shell(d,'Results')
box(d,320,190,1140,90,'Saved or not saved status','')
box(d,320,305,1140,110,'Case summary','Risk    Verdict    Confidence    Evidence count')
box(d,320,440,1140,85,'[ Overview ]   [ Supporting evidence ]   [ Technical details ]   [ Next steps ]','',size=21)
box(d,320,550,340,220,'Assessment','Score with limits\nUncertainty is visible\n[ Review conclusion ]')
box(d,685,550,775,220,'Findings','Evidence-linked observations\nExpandable details with severity labels\nNo colour-only meaning')
box(d,320,795,1140,100,'Recovery section','Choose what actually happened before following the suggested steps.')
im.save(OUT/'wireframe-results.png')

states=[('Empty','Explain the input and offer a clear first action.'),('Loading','Rotating shield and text; prevent duplicate submission.'),('Slow network','After 15 seconds: explain delay, no invented countdown.'),('No internet','Reconnect notice; retain loaded public guidance.'),('Request error','Clear reason and next action; no internal error dump.'),('No saved cases','Show first-case action after a successful empty response.'),('No search result','Explain preview-only scope; offer Clear search.'),('Permission denied','Explain email confirmation or access requirement.'),('Session expired','Clear private state and open the sign-in form.'),('Form validation','Identify missing or invalid input beside the control.'),('Success','Show saved result or confirmed active-storage deletion.'),('Not saved','Warn that the result is not in history; do not imply success.')]
for page in range(2):
 im,d=canvas('0'+str(page+4)+'  Interface states '+str(page*6+1)+' to '+str(page*6+6))
 for i,(title,body) in enumerate(states[page*6:page*6+6]):
  x=35+(i%2)*730;y=95+(i//2)*265
  box(d,x,y,700,240,title,body,size=30)
 im.save(OUT/('wireframe-states-'+str(page+1)+'.png'))
