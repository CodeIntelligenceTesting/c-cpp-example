//
// Created by philip on 22/11/23.
//

#include <stdio.h>
#include "person.h"



void printPersonsName(const Person* person) {
    printf("\nPrinting persons name:\n");
    printf("%s\n", person->name );
}
void printPersonsAge(const Person* person) {
    printf("\nPrinting persons name:\n");
    printf("%d\n", person->age );
}

char* getPersonsName(const Person* person) {
    return (char *) &person->name;
}
int getPersonsAge(const Person* person) {
    return person->age;
}