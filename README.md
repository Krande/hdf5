HDF5 version 2.0.0 currently under development

![HDF5 Logo](doxygen/img/HDF5.png)

[![develop cmake build status](https://img.shields.io/github/actions/workflow/status/HDFGroup/hdf5/cmake.yml?branch=develop&label=HDF5%20develop%20CMake%20CI)](https://github.com/HDFGroup/hdf5/actions/workflows/cmake.yml?query=branch%3Adevelop)
[![develop autotools build status](https://img.shields.io/github/actions/workflow/status/HDFGroup/hdf5/autotools.yml?branch=develop&label=HDF5%20develop%20Autotools%20CI)](https://github.com/HDFGroup/hdf5/actions/workflows/autotools.yml?query=branch%3Adevelop)
[![HDF-EOS5 build status](https://img.shields.io/github/actions/workflow/status/HDFGroup/hdf5/hdfeos5.yml?branch=develop&label=HDF-EOS5)](https://github.com/HDFGroup/hdf5/actions/workflows/hdfeos5.yml?query=branch%3Adevelop)
[![netCDF build status](https://img.shields.io/github/actions/workflow/status/HDFGroup/hdf5/netcdf.yml?branch=develop&label=netCDF)](https://github.com/HDFGroup/hdf5/actions/workflows/netcdf.yml?query=branch%3Adevelop)
[![h5py build status](https://img.shields.io/github/actions/workflow/status/HDFGroup/hdf5/h5py.yml?branch=develop&label=h5py)](https://github.com/HDFGroup/hdf5/actions/workflows/h5py.yml?query=branch%3Adevelop)
[![CVE regression](https://img.shields.io/github/actions/workflow/status/HDFGroup/hdf5/cve.yml?branch=develop&label=CVE)](https://github.com/HDFGroup/hdf5/actions/workflows/cve.yml?query=branch%3Adevelop)
[![HDF5 VOL connectors build status](https://img.shields.io/github/actions/workflow/status/HDFGroup/hdf5/vol.yml?branch=develop&label=HDF5-VOL)](https://github.com/HDFGroup/hdf5/actions/workflows/vol.yml?query=branch%3Adevelop)
[![HDF5 VFD build status](https://img.shields.io/github/actions/workflow/status/HDFGroup/hdf5/vfd.yml?branch=develop&label=HDF5-VFD)](https://github.com/HDFGroup/hdf5/actions/workflows/vfd.yml?query=branch%3Adevelop)
[![BSD](https://img.shields.io/badge/License-BSD-blue.svg)](https://github.com/HDFGroup/hdf5/blob/develop/LICENSE)
[![OSS-Fuzz Status](https://oss-fuzz-build-logs.storage.googleapis.com/badges/hdf5.svg)](https://oss-fuzz-build-logs.storage.googleapis.com/index.html#hdf5)

[HPC configure/build/test results](https://my.cdash.org/index.php?project=HDF5)

*Please refer to the release_docs/INSTALL file for installation instructions.*

This repository contains a high-performance library's source code and a file format
specification that implements the HDF5® data model. The model has been adopted across
many industries, and this implementation has become a de facto data management standard
in science, engineering, and research communities worldwide.

The HDF Group is the developer, maintainer, and steward of HDF5 software. Find more
information about The HDF Group, the HDF5 Community, and other HDF5 software projects,
tools, and services at [The HDF Group's website](https://www.hdfgroup.org/). 

DOCUMENTATION
-------------
Documentation for all HDF software is available at:

   https://support.hdfgroup.org/documentation/index.html

Documentation for the current HDF5 library release is available at:

   https://support.hdfgroup.org/releases/hdf5/latest-docs.html

The latest Doxygen documentation generated on changes to `develop`, which does **not** correspond to any particular library release, is available at:

   https://hdfgroup.github.io/hdf5/develop 

See the [RELEASE.txt](release_docs/RELEASE.txt) file in the [release_docs/](release_docs/) directory for information specific
to the features and updates included in this release of the library.

Several more files are located within the [release_docs/](release_docs/) directory with specific
details for several common platforms and configurations.

    INSTALL - Start Here. General instructions for compiling and installing the library
    INSTALL_CMAKE  - instructions for building with CMake (Kitware.com)
    INSTALL_parallel - instructions for building and configuring Parallel HDF5
    INSTALL_Windows and INSTALL_Cygwin - MS Windows installations.



HELP AND SUPPORT
----------------
Information regarding Help Desk and Support services is available at

   https://help.hdfgroup.org 



FORUM and NEWS
--------------
The [HDF Forum](https://forum.hdfgroup.org) is provided for public announcements and discussions
of interest to the general HDF5 Community.

   - News and Announcements
   https://forum.hdfgroup.org/c/news-and-announcements-from-the-hdf-group

   - HDF5 Topics
   https://forum.hdfgroup.org/c/hdf5

These forums are provided as an open and public service for searching and reading.
Posting requires completing a simple registration and allows one to join in the
conversation.  Please read the [instructions](https://forum.hdfgroup.org/t/quickstart-guide-welcome-to-the-new-hdf-forum
) pertaining to the Forum's use and configuration.

RELEASE SCHEDULE
----------------

![HDF5 release schedule](doc/img/release-schedule.png) 

HDF5 does not follow a regular release schedule. Instead, updates are based on the
introduction of new features and the resolution of bugs. However, we aim to have at
least one annual release for each maintenance branch. Please note that the future
HDF5 releases listed on this schedule are tentative.

> [!IMPORTANT]
> In subsequent releases after 1.14, HDF5 will adopt [semantic versioning](https://semver.org/).
> Therefore, the upcoming major release will be designated as 2.0.0.

| Release | New Features |
| ------- | ------------ |
| 2.0.0 | Drop Autotools support, drop the HDF5 <--> GIF tools, add complex number support, update library defaults (cache sizes, etc.) |
| FUTURE | Multi-threaded HDF5, crashproofing / metadata journaling, Full (VFD) SWMR, encryption, digital signatures, sparse datasets, improved storage for variable-length datatypes, better Unicode support (especially on Windows) |

[A list of planned HDF5 2.0 features and bugfixes can be found here.](https://github.com/HDFGroup/hdf5/wiki/HDF5-2.0-Planning)

This list of feature release versions is tentative, and the release
in which a feature is introduced may change.


SNAPSHOTS, PREVIOUS RELEASES AND SOURCE CODE
--------------------------------------------
Periodically development code snapshots are provided at the following URL:

   https://github.com/HDFGroup/hdf5/releases/tag/snapshot

Source packages for current and previous releases are located at:

   hdf5 1.14 releases:
   https://support.hdfgroup.org/releases/hdf5/v1_14/index.html

   Archived releases:
   https://support.hdfgroup.org/archive/support/ftp/HDF5/releases/index.html

Development code is available at our Github location:

   https://github.com/HDFGroup/hdf5.git

