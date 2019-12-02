#ifndef MAINWINDOW_H
#define MAINWINDOW_H
#include <QMainWindow>
#include<QtWidgets>
#include <tlhelp32.h>
#include <tchar.h>
#include <stdio.h>
#include <winternl.h>
#include <QString>
#include<stdlib.h>
#include <cstdlib>
#include<dbghelp.h>
#include <libloaderapi.h>
#include <stdexcept>
#include <windows.h>
#include <Aclapi.h>
#include <WinError.h>
#include <Sddl.h>
#include <tchar.h>
#include <winnt.h>
#pragma comment(lib, "ws2_32.lib")
QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_pushButton_clicked();
    void on_listView_indexesMoved(const QModelIndexList &indexes);
    void on_listView_2_indexesMoved(const QModelIndexList &indexes);
    void on_pushButton_2_clicked();
    void on_lineEdit_cursorPositionChanged(int arg1, int arg2);
    void on_pushButton_3_clicked();
    void on_lineEdit_2_cursorPositionChanged(int arg1, int arg2);
    void on_lineEdit_3_cursorPositionChanged(int arg1, int arg2);
    void on_pushButton_4_clicked();
    void on_lineEdit_4_cursorPositionChanged(int arg1, int arg2);
    void on_pushButton_5_clicked();
    void on_listView_3_indexesMoved(const QModelIndexList &indexes);
    void on_pushButton_6_clicked();
    void on_lineEdit_5_cursorPositionChanged(int arg1, int arg2);

    void on_pushButton_7_clicked();

    void on_pushButton_8_clicked();

    void on_lineEdit_7_cursorPositionChanged(int arg1, int arg2);

    void on_lineEdit_6_cursorPositionChanged(int arg1, int arg2);

private:
    Ui::MainWindow *ui;
};
#endif // MAINWINDOW_H
