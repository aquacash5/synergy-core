/*
 * synergy -- mouse and keyboard sharing utility
 * Copyright (C) 2012-2016 Symless Ltd.
 * Copyright (C) 2008 Volker Lanz (vl@fidra.de)
 *
 * This package is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * found in the file LICENSE that should have accompanied this file.
 *
 * This package is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "QSynergyApplication.h"
#include "MainWindow.h"

#include <QtCore>
#include <QtGui>

QSynergyApplication *QSynergyApplication::s_Instance = NULL;

QSynergyApplication::QSynergyApplication(int &argc, char **argv)
    : QApplication(argc, argv) {
  s_Instance = this;

  QFontDatabase::addApplicationFont(":/res/fonts/Arial.ttf");
  QFont Arial("Arial");
  Arial.setPixelSize(13);
  Arial.setStyleHint(QFont::SansSerif);
  setFont(Arial);
}

QSynergyApplication::~QSynergyApplication() {}

void QSynergyApplication::commitData(QSessionManager &) {
  foreach (QWidget *widget, topLevelWidgets()) {
    MainWindow *mainWindow = qobject_cast<MainWindow *>(widget);
    if (mainWindow)
      mainWindow->saveSettings();
  }
}

QSynergyApplication *QSynergyApplication::getInstance() { return s_Instance; }
