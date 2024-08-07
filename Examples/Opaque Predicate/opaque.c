#include <stdio.h>

int main()
{
    int a = 3;
    int b = 10;
    int c = 34;
    int d = ((a + b) * c * 2 + 4)/111;

    if (d == 8)
    {
        printf("Hello Watermark! \n");
    }

    return 0;
}