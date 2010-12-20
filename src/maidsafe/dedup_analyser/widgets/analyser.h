#ifndef ANALYSER_H
#define ANALYSER_H

#include <QWidget>

namespace Ui {
    class Analyser;
}

class Analyser : public QWidget
{
    Q_OBJECT

public:
    explicit Analyser(QWidget *parent = 0);
    ~Analyser();

private:
    Ui::Analyser *ui;
};

#endif // ANALYSER_H
