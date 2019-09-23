"""
This file is part of the Redqueen fuzzer.

Sergej Schumilo, 2019 <sergej@schumilo.de> 
Cornelius Aschermann, 2019 <cornelius.aschermann@rub.de> 

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with Redqueen.  If not, see <http://www.gnu.org/licenses/>. 
"""
__author__ = 'sergej'
import glob

from array import array
from fuzzer.technique.helper import *
from fuzzer.technique.havoc_handler import *
from common.config import FuzzerConfiguration
from common.debug import logger

def load_dict(file_name):
    f = open(file_name)
    dict_entries = []
    for line in f:
        if not line.startswith("#"):
            try:
                dict_entries.append((line.split("=\"")[1].split("\"\n")[0]).decode("string_escape"))
            except:
                pass
    f.close()
    return dict_entries

if FuzzerConfiguration().argument_values["I"]:
    set_dict(load_dict(FuzzerConfiguration().argument_values["I"]))
    append_handler(havoc_dict)
    append_handler(havoc_dict)

location_findings = FuzzerConfiguration().argument_values['work_dir'] + "/findings/"
location_corpus = FuzzerConfiguration().argument_values['work_dir'] + "/corpus/"

def havoc_range(perf_score):

    max_iterations = int(perf_score * 2.5)

    if max_iterations < AFL_HAVOC_MIN:
        max_iterations = AFL_HAVOC_MIN

    return max_iterations


def mutate_seq_havoc_array(data, func, max_iterations, stacked=True, resize=False, files_to_splice=None):

    reseed()
    if resize:
        copy = array('B', data.tostring() + data.tostring())
    else:
        copy = array('B', data.tostring())

    cnt = 0
    for i in range(max_iterations):

        copy = array('B', data.tostring())

        value = RAND(AFL_HAVOC_STACK_POW2)

        for j in range(1 << (1 + value)):
            handler = havoc_handler[RAND(len(havoc_handler))]
            copy = handler(copy)
            if len(copy) >= 64<<10:
                copy = copy[:(64<<10)]
        func(copy.tostring())
    pass


def mutate_seq_splice_array(data, func, max_iterations, kafl_state, stacked=True, resize=False):
    files = []
    files+=glob.glob(location_findings + "crash/*")
    files+=glob.glob(location_findings + "kasan/*")
    files+=glob.glob(location_findings + "timeout/*")
    files+=glob.glob(location_corpus + "*")
    random.shuffle(files)
    mutate_seq_havoc_array( havoc_splicing(data, files) , func, max_iterations, stacked=stacked, resize=resize)
