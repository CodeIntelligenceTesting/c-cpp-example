//
// Created by philip on 22/11/23.
//

#ifndef AUTOMOTIVE_FUZZING_TESTSUITE_PERSON_H
#define AUTOMOTIVE_FUZZING_TESTSUITE_PERSON_H

#endif //AUTOMOTIVE_FUZZING_TESTSUITE_PERSON_H


typedef struct Person  {
    const char name[100];
    const char secret[100];
    int age;

} Person;

char* getPersonsName(const Person* person);
int getPersonsAge(const Person* person);

void setPersonsName(Person* person, const char* name);
void setPersonsAge(Person* person, int age);