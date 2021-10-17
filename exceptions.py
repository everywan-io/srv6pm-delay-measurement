#!/usr/bin/python

##########################################################################
# Copyright (C) 2021 Carmine Scarpitta - (University of Rome "Tor Vergata")
# www.uniroma2.it/netgroup
#
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Exceptions used by the Controller module.
#
# @author Carmine Scarpitta <carmine.scarpitta@uniroma2.it>
#


"""
This module provides several exceptions used by the Controller module.
"""


from six import MAXSIZE


class NodeIdAlreadyExistsError(Exception):
    """Raised when the Node ID is already used.

    Parameters
    ----------
    msg : str
        Human readable string describing the exception.
    code : :obj:`int`, optional
        Numeric error code.

    Attributes
    ----------
    msg : str
        Human readable string describing the exception.
    code : int
        Numeric error code.

    """


class NodeIdNotFoundError(Exception):
    """Raised when Node ID does not correspond to any existing node.

    Parameters
    ----------
    msg : str
        Human readable string describing the exception.
    code : :obj:`int`, optional
        Numeric error code.

    Attributes
    ----------
    msg : str
        Human readable string describing the exception.
    code : int
        Numeric error code.

    """


class NotAStampSenderError(Exception):
    """Raised when Node is not a STAMP Sender.

    Parameters
    ----------
    msg : str
        Human readable string describing the exception.
    code : :obj:`int`, optional
        Numeric error code.

    Attributes
    ----------
    msg : str
        Human readable string describing the exception.
    code : int
        Numeric error code.

    """


class NotAStampReflectorError(Exception):
    """Raised when Node is not a STAMP Reflector.

    Parameters
    ----------
    msg : str
        Human readable string describing the exception.
    code : :obj:`int`, optional
        Numeric error code.

    Attributes
    ----------
    msg : str
        Human readable string describing the exception.
    code : int
        Numeric error code.

    """


class InvalidStampNodeError(Exception):
    """Raised when Node is neither a STAMP Sender nor a STAMP Reflector.

    Parameters
    ----------
    msg : str
        Human readable string describing the exception.
    code : :obj:`int`, optional
        Numeric error code.

    Attributes
    ----------
    msg : str
        Human readable string describing the exception.
    code : int
        Numeric error code.

    """


class NodeInitializedError(Exception):
    """Raised when attempting to initialize an already inizialized node.

    Parameters
    ----------
    msg : str
        Human readable string describing the exception.
    code : :obj:`int`, optional
        Numeric error code.

    Attributes
    ----------
    msg : str
        Human readable string describing the exception.
    code : int
        Numeric error code.

    """


class NodeNotInitializedError(Exception):
    """Raised when attempting to perform an operation on a node that has not
    been initialized.

    Parameters
    ----------
    msg : str
        Human readable string describing the exception.
    code : :obj:`int`, optional
        Numeric error code.

    Attributes
    ----------
    msg : str
        Human readable string describing the exception.
    code : int
        Numeric error code.

    """


class InitSTAMPNodeError(Exception):
    """Raised when an error occurs during the initialization of a STAMP node.

    Parameters
    ----------
    msg : str
        Human readable string describing the exception.

    Attributes
    ----------
    msg : str
        Human readable string describing the exception.

    """

    def __init__(self, msg=''):
        super().__init__(msg)


class ResetSTAMPNodeError(Exception):
    """Raised when an error occurs during the reset operation of a STAMP node.

    Parameters
    ----------
    msg : str
        Human readable string describing the exception.

    Attributes
    ----------
    msg : str
        Human readable string describing the exception.

    """

    def __init__(self, msg=''):
        super().__init__(msg)


class CreateSTAMPSessionError(Exception):
    """Raised when an error occurs during the creation of a STAMP Session.

    Parameters
    ----------
    msg : str
        Human readable string describing the exception.

    Attributes
    ----------
    msg : str
        Human readable string describing the exception.

    """

    def __init__(self, msg=''):
        super().__init__(msg)


class StartSTAMPSessionError(Exception):
    """Raised when an error occurs when attempting to start a STAMP Session.

    Parameters
    ----------
    msg : str
        Human readable string describing the exception.

    Attributes
    ----------
    msg : str
        Human readable string describing the exception.

    """

    def __init__(self, msg=''):
        super().__init__(msg)


class StopSTAMPSessionError(Exception):
    """Raised when an error occurs when attempting to stop a STAMP Session.

    Parameters
    ----------
    msg : str
        Human readable string describing the exception.

    Attributes
    ----------
    msg : str
        Human readable string describing the exception.

    """

    def __init__(self, msg=''):
        super().__init__(msg)


class GetSTAMPResultsError(Exception):
    """Raised when an error occurs when attempting to retrieve the results of
    a STAMP Session.

    Parameters
    ----------
    msg : str
        Human readable string describing the exception.

    Attributes
    ----------
    msg : str
        Human readable string describing the exception.

    """

    def __init__(self, msg=''):
        super().__init__(msg)


class DestroySTAMPSessionError(Exception):
    """Raised when an error occurs when attempting to destroy a STAMP Session.

    Parameters
    ----------
    msg : str
        Human readable string describing the exception.

    Attributes
    ----------
    msg : str
        Human readable string describing the exception.

    """

    def __init__(self, msg=''):
        self.msg = msg
        super().__init__(self.msg)


class STAMPSessionNotFoundError(Exception):
    """Raised when attempting to perform an operation on a non-existing STAMP
    Session.

    Parameters
    ----------
    ssid : int
        16-bit STAMP Session Identifier (SSID).

    Attributes
    ----------
    msg : str
        Human readable string describing the exception.

    """

    def __init__(self, ssid=None):
        self.msg = ''
        if ssid is not None:
            self.msg = 'STAMP Session {ssid} does not exist'.format(ssid=ssid)
        super().__init__(self.msg)
