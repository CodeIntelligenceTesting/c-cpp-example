//
// Created by philip on 22/11/23.
//

#ifndef AUTOMOTIVE_FUZZING_TESTSUITE_PERSON_H
#define AUTOMOTIVE_FUZZING_TESTSUITE_PERSON_H

#endif //AUTOMOTIVE_FUZZING_TESTSUITE_PERSON_H


typedef struct Person  {
    const char name[100];
    const int age;
    const char secret[100];
} Person;

void printPersonsName(const Person* person);
void printPersonsAge(const Person* person);
char* getPersonsName(const Person* person);
int getPersonsAge(const Person* person);