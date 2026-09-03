#ifndef HAVOC_UPLOAD_DIALOG_HPP
#define HAVOC_UPLOAD_DIALOG_HPP

#include <QDialog>
#include <QLineEdit>
#include <QPushButton>

class UploadDialog : public QDialog
{
    Q_OBJECT

public:
    /**
     * @param defaultRemoteDir  When non-empty, the remote path field is
     *                          pre-filled with this directory (a trailing
     *                          '\\' is appended if missing). Picking a local
     *                          file then auto-completes the remote path with
     *                          the local basename.
     */
    explicit UploadDialog( QWidget* parent = nullptr,
                           const QString& defaultRemoteDir = QString() );

    QString localFilePath() const;
    QString remotePath()    const;

private slots:
    void onBrowse();
    void onLocalPathChanged( const QString& );

private:
    QLineEdit*   inputLocal   = nullptr;
    QPushButton* buttonBrowse = nullptr;
    QLineEdit*   inputRemote  = nullptr;
    QPushButton* buttonUpload = nullptr;
    QPushButton* buttonCancel = nullptr;

    bool remoteEndsWithSep() const;
};

#endif
