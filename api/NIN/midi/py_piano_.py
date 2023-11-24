##
## https://gist.github.com/alan-welsh/7cefe4f592860f1ef5ee7b22cf8d775b
##

# Alan Welsh
# alanwelsh13@gmail.com
# 13/04/2018

import math
import midiparser
import pymel.core as pm
note_list = ['C', 'Cs', 'D', 'Eb', 'E', 'F', 'Fs', 'G', 'Gs', 'A', 'Bb', 'B']


def get_note_name(note):
    octave = int(math.ceil(note / 12))
    note_index = note % 12
    return note_list[note_index] + '_' + repr(octave)


def key_press(curve_name, frame_number, velocity):
    if velocity > 0:
        frame_offset = int(math.ceil(127 / velocity))
        pm.setKeyframe(curve_name, attribute='Push_Key', v=0, t=frame_number - frame_offset)
        pm.setKeyframe(curve_name, attribute='Push_Key', v=1, t=frame_number)
    elif velocity == 0:
        pm.setKeyframe(curve_name, attribute='Push_Key', v=1, t=frame_number - 1)
        pm.setKeyframe(curve_name, attribute='Push_Key', v=0, t=frame_number + 2)


def parse_midi(file_name):
    midi = midiparser.File(file_name)
    timebase = midi.division
    frames_per_second = 24
    start_offset = 30
    end_offset = 100
    tempo = 0
    maxTime = 0
    frame_number = 0

    for track in midi.tracks:
        for event in track.events:
            if event.type == midiparser.voice.NoteOn:
                frame_number = int(math.ceil(event.absolute * tempo * frames_per_second / timebase / 1000000) + start_offset)
                key_press(get_note_name(event.detail.note_no), frame_number, event.detail.velocity)
                if event.absolute > maxTime:
                    maxTime = event.absolute
            elif event.type == midiparser.meta.SetTempo:
                tempo = event.detail.tempo

    number_of_frames = int(math.ceil(maxTime * tempo * frames_per_second / timebase / 1000000) + start_offset) + end_offset
    pm.playbackOptions(minTime='1', maxTime=number_of_frames, animationEndTime=number_of_frames, animationStartTime='1')


file_name = pm.fileDialog(directoryMask='*.mid')

if file_name is None:
    print 'No file choosen'
else:
    parse_midi(file_name)

##
##    
