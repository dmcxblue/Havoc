#include <UserInterface/Dialogs/UploadDialog.hpp>

#include <QFileDialog>
#include <QFileInfo>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>

UploadDialog::UploadDialog( QWidget* parent, const QString& defaultRemoteDir )
    : QDialog( parent )
{
    setWindowTitle( "Upload File" );
    resize( 560, 140 );
    setModal( true );

    auto* grid = new QGridLayout( this );

    auto* localLabel  = new QLabel( "Local file:",  this );
    auto* remoteLabel = new QLabel( "Remote path:", this );

    inputLocal = new QLineEdit( this );
    inputLocal->setPlaceholderText( "Pick a local file to upload" );

    buttonBrowse = new QPushButton( "Browse...", this );

    inputRemote = new QLineEdit( this );
    inputRemote->setPlaceholderText( R"(e.g. C:\Users\Public\payload.exe)" );

    if ( ! defaultRemoteDir.isEmpty() )
    {
        QString dir = defaultRemoteDir;
        if ( ! dir.endsWith( '\\' ) && ! dir.endsWith( '/' ) )
            dir += '\\';
        inputRemote->setText( dir );
    }

    buttonUpload = new QPushButton( "Upload", this );
    buttonCancel = new QPushButton( "Cancel", this );
    buttonUpload->setDefault( true );

    grid->addWidget( localLabel,   0, 0 );
    grid->addWidget( inputLocal,   0, 1 );
    grid->addWidget( buttonBrowse, 0, 2 );

    grid->addWidget( remoteLabel,  1, 0 );
    grid->addWidget( inputRemote,  1, 1, 1, 2 );

    auto* btnRow = new QHBoxLayout();
    btnRow->addStretch();
    btnRow->addWidget( buttonCancel );
    btnRow->addWidget( buttonUpload );
    grid->addLayout( btnRow, 2, 0, 1, 3 );

    connect( buttonBrowse, &QPushButton::clicked, this, &UploadDialog::onBrowse );
    connect( buttonCancel, &QPushButton::clicked, this, &QDialog::reject );
    connect( buttonUpload, &QPushButton::clicked, this, [this]() {
        if ( inputLocal->text().trimmed().isEmpty() ) {
            QMessageBox::warning( this, "Upload", "Pick a local file first." );
            return;
        }
        if ( inputRemote->text().trimmed().isEmpty() ) {
            QMessageBox::warning( this, "Upload", "Remote path is empty." );
            return;
        }
        if ( remoteEndsWithSep() ) {
            QMessageBox::warning( this, "Upload",
                "Remote path ends with a separator — include a filename." );
            return;
        }
        accept();
    } );

    connect( inputLocal, &QLineEdit::textChanged,
             this, &UploadDialog::onLocalPathChanged );
}

QString UploadDialog::localFilePath() const
{
    return inputLocal->text().trimmed();
}

QString UploadDialog::remotePath() const
{
    return inputRemote->text().trimmed();
}

bool UploadDialog::remoteEndsWithSep() const
{
    const QString r = inputRemote->text();
    return r.endsWith( '\\' ) || r.endsWith( '/' );
}

void UploadDialog::onBrowse()
{
    QString picked = QFileDialog::getOpenFileName(
        this, "Select file to upload", QString(), "All files (*)"
    );
    if ( picked.isEmpty() )
        return;
    inputLocal->setText( picked );
}

void UploadDialog::onLocalPathChanged( const QString& path )
{
    /* Auto-complete: if the remote field is empty or clearly a directory
       (ends with a separator), append the local basename so the user can
       just click Upload. Otherwise leave the field alone — the user has
       already typed a target filename. */
    if ( path.isEmpty() )
        return;

    const QString base    = QFileInfo( path ).fileName();
    const QString current = inputRemote->text();

    if ( current.isEmpty() )
        inputRemote->setText( base );
    else if ( remoteEndsWithSep() )
        inputRemote->setText( current + base );
}
