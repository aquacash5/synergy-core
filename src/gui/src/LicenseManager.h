/*
 * synergy -- mouse and keyboard sharing utility
 * Copyright (C) 2015 Synergy Ltd.
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

#pragma once

#include <ActivationNotifier.h>
#include <QObject>
#include <shared/EditionType.h>
#include <shared/SerialKey.h>
#include <utility>

#include "LicenseRegistry.h"

class AppConfig;

class LicenseManager : public QObject {
  Q_OBJECT

public:
  LicenseManager(AppConfig *appConfig);
  void setSerialKey(SerialKey serialKey, bool acceptExpired = false);
  void refresh();
  Edition activeEdition() const;
  QString activeEditionName() const;
  const SerialKey &serialKey() const;
  void skipActivation() const;
  void notifyUpdate(QString fromVersion, QString toVersion) const;
  static QString getEditionName(Edition edition, bool trial = false);
  void notifyActivation(QString identity) const;
  QString getLicenseNotice() const;

private:
  AppConfig *m_AppConfig;
  SerialKey m_serialKey;
  LicenseRegistry m_registry;

public slots:
  void validateSerialKey() const;
  void registerLicense();

signals:
  void editionChanged(Edition) const;
  void InvalidLicense() const;
  void showLicenseNotice(const QString &notice) const;

protected:
  QString getTrialNotice() const;
  QString getTemporaryNotice() const;
};
